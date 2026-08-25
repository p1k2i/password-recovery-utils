#!/usr/bin/env python3
"""
crack_runner.py - Drive dict_gen.py + hashcat together.

Starts dict_gen.py generating dictionary files (dict-1.txt, dict-2.txt, ...)
into a work directory, and as soon as each file is finished being written,
runs `hashcat -a 0 -m <type> <target> <file>` against it -- one hashcat run
at a time, in file order -- while generation keeps going in the background.
Stops as soon as the target is cracked (checked via `hashcat --show` after
every run), tears down the still-running generator, and reports the result.

A dictionary file is only handed to hashcat once dict_gen.py has moved on
to the next one (or has exited), so a file is never read while it might
still be appended to.

Example:
    python crack_runner.py seed.json hash.txt -m 1000 \
        --work-dir ./run1 \
        --dictgen-args "--min-length 4 --max-length 10 --max-repeat 2" \
        --performance
    # --performance is shorthand for handing hashcat "--force -O -w 3"; the
    # equivalent spelled out by hand would be --hashcat-args "--force -O -w 3"

Resuming a stopped run:
    python crack_runner.py --resume ./run1

The work directory (--work-dir, e.g. ./run1) is a self-contained
checkpoint: it holds a state.json recording every argument the first run
was given, a local copy of the seed dictionary, and a local copy of the
hash target (if the target was a file rather than a bare hash string).
--resume accepts either that state.json directly or the directory
containing it. No other arguments may be given alongside --resume --
every original parameter is replayed from the saved state, so the run
resumes exactly as configured the first time. The only things NOT taken
from the saved state are the python interpreter and the dict_gen.py
script path, which are always re-resolved the normal way (relative to
wherever crack_runner.py is currently being run from) -- those are the
"program installed on this PC" side of things, not part of the portable
run folder, so the folder can be copied to another machine or location
and resumed there as long as dict_gen.py/crack_runner.py and hashcat are
available on that machine too.

Resuming tells dict_gen.py (via its --skip-count/--start-index flags) how
many words and files were already attacked in the previous invocation --
generation is fully deterministic (same seed and arguments always
produce the same words in the same order), so it picks up generating
and numbering files right after them (e.g. out-4.txt, out-5.txt, ...)
instead of restarting from out-1.txt. hashcat only resumes attacking
from the first word list that wasn't tried yet, so no GPU time is wasted
redoing already-tried passwords, and no CPU/disk time is wasted
regenerating and discarding files already known not to contain the
password.
"""

import argparse
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
STATE_FILENAME = "state.json"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a brute-force dictionary with dict_gen.py and feed it to "
                    "hashcat file by file, stopping as soon as the hash is cracked."
    )
    parser.add_argument("seed", type=Path, nargs="?", default=None,
                        help="Seed dictionary file passed to dict_gen.py (.txt or .json). "
                             "Not given (and not allowed) with --resume.")
    parser.add_argument("target", nargs="?", default=None,
                        help="What hashcat should attack: a hash string, or a path to a "
                             "file containing hash(es). Not given (and not allowed) with "
                             "--resume.")
    parser.add_argument("-m", "--hash-type", type=int, default=None,
                        help="hashcat -m hash type. Required unless --resume is given.")
    parser.add_argument("--resume", dest="resume_path", type=Path, default=None,
                        metavar="PATH",
                        help="Resume a previously stopped run instead of starting a new one. "
                             "PATH is either the --work-dir from that run or its state.json "
                             "directly. Must be the ONLY argument given -- every original "
                             "parameter (seed, target, hash type, dict_gen/hashcat flags, "
                             "performance mode, etc.) is replayed from the run's saved state, "
                             "so it cannot be changed at resume time. See 'Resuming a stopped "
                             "run' above.")
    parser.add_argument("--work-dir", type=Path, default=None,
                        help="Directory to generate dictionary files into "
                             "(default: ./hashcat_run_<timestamp>)")
    parser.add_argument("--prefix", default="dict",
                        help="Output file prefix passed to dict_gen.py (default: 'dict')")
    parser.add_argument("--dict-gen-script", type=Path, default=None,
                        help="Path to dict_gen.py (default: look next to this script)")
    parser.add_argument("--python", default=sys.executable,
                        help="Python executable used to run dict_gen.py (default: current interpreter)")
    parser.add_argument("--hashcat-bin", default="hashcat",
                        help="hashcat executable (default: 'hashcat')")
    parser.add_argument("--hashcat-cwd", type=Path, default=None,
                        help="Directory to run hashcat from. hashcat looks up ./OpenCL and "
                             "./modules relative to its *working directory*, not its executable's "
                             "location, so a portable install fails with e.g. './OpenCL/: No such "
                             "file or directory' if launched from elsewhere. Default: auto-detected "
                             "as the folder containing the hashcat executable, if it looks like a "
                             "portable install (has an OpenCL/ or modules/ subfolder there).")
    parser.add_argument("--dictgen-args", default="",
                        help="Extra arguments passed through to dict_gen.py, quoted as one string, "
                             "e.g. \"--min-length 4 --max-length 10 --max-repeat 2\"")
    parser.add_argument("--hashcat-args", default="",
                        help="Extra arguments passed through to hashcat, quoted as one string, "
                             "e.g. \"--force -O -w 3\"")
    parser.add_argument("--performance", action="store_true",
                        help="Shorthand for handing hashcat a standard set of speed-oriented "
                             "flags: '-O' (optimized kernels -- faster, but caps the max "
                             "supported password length for some hash types), '-w N' (workload "
                             "profile, see --workload), and '--force' (skip hashcat's hardware "
                             "warnings, e.g. for a GPU it considers unstable). Combine with "
                             "--hashcat-args for anything these don't cover -- your own flags win "
                             "if they overlap (e.g. --hashcat-args \"-w 2\" downgrades the workload "
                             "--performance would otherwise set).")
    parser.add_argument("--workload", type=int, default=3, choices=(1, 2, 3, 4),
                        help="Workload profile used by --performance: 1=Low, 2=Default, 3=High, "
                             "4=Nightmare (can make the GPU unresponsive for other use). Default: "
                             "3. Has no effect unless --performance is also passed.")
    parser.add_argument("--poll-interval", type=float, default=1.0,
                        help="Seconds between checks for newly finished dictionary files (default: 1.0)")
    parser.add_argument("--keep-dictionaries", action="store_true",
                        help="Keep each generated dictionary file after hashcat has tried it "
                             "(default: delete it right after, to save disk)")
    parser.add_argument("--force", action="store_true",
                        help="Allow reusing a --work-dir that already has files matching "
                             "the output prefix (they are deleted first)")
    parser.add_argument("--log-file", type=Path, default=None,
                        help="Path to the run history log file "
                             "(default: <work-dir>/crack_runner.log)")
    parser.add_argument("--log-level", choices=LOG_LEVELS, default="INFO",
                        help="Verbosity of the file log (default: INFO). DEBUG additionally logs "
                             "the exact dict_gen.py/hashcat command lines run; WARNING/ERROR only "
                             "logs problems, dropping the step-by-step file-by-file history.")
    parser.add_argument("--log-max-bytes", type=int, default=5 * 1024 * 1024,
                        help="Rotate the log file after it reaches this size in bytes "
                             "(default: 5MB); keeps the log from growing without bound on long runs")
    parser.add_argument("--log-backups", type=int, default=3,
                        help="Number of rotated log files to keep (default: 3)")
    return parser


def setup_logger(log_path: Path, level: str, max_bytes: int, backups: int) -> logging.Logger:
    """File-only run history logger: one compact line per event (config,
    file taken/processed/deleted, crack result), rotated so it can't grow
    without bound over a long-running session."""
    logger = logging.getLogger("crack_runner")
    logger.setLevel(getattr(logging, level))
    logger.propagate = False
    handler = RotatingFileHandler(
        log_path, maxBytes=max_bytes, backupCount=backups, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    return logger


def resolve_dict_gen_script(explicit: Optional[Path]) -> Path:
    if explicit is not None:
        if not explicit.is_file():
            raise FileNotFoundError(f"dict_gen.py not found at {explicit}")
        return explicit
    candidate = Path(__file__).resolve().parent / "dict_gen.py"
    if not candidate.is_file():
        raise FileNotFoundError(
            "dict_gen.py not found next to crack_runner.py -- pass --dict-gen-script explicitly"
        )
    return candidate


def discover_files(work_dir: Path, prefix: str) -> Dict[int, Path]:
    """Map file index -> path for every <prefix>-N.txt file currently in
    work_dir."""
    pattern = re.compile(rf"^{re.escape(prefix)}-(\d+)\.txt$")
    found = {}
    for path in work_dir.glob(f"{prefix}-*.txt"):
        match = pattern.match(path.name)
        if match:
            found[int(match.group(1))] = path
    return found


def estimate_progress_total(dict_gen_script: Path, seed: Path, dictgen_extra: list,
                             logger: logging.Logger) -> Tuple[Optional[int], bool]:
    """Reuse dict_gen.py's own estimate_total()/load_dictionary() (loaded
    from the resolved script path) to get the same word-count estimate it
    shows in its own progress bar, so the file log's % matches. Returns
    (None, False) if anything about this goes wrong -- progress logging
    then just drops the % and works off raw counts instead."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("dict_gen_for_estimate", dict_gen_script)
        dict_gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dict_gen)
        dg_args = dict_gen.build_arg_parser().parse_args([str(seed)] + dictgen_extra)
        rules = dict_gen.load_dictionary(seed)
        total = dict_gen.estimate_total(rules.pieces, dg_args.min_length, dg_args.max_length)
        approx = dg_args.max_repeat is not None or rules.has_constraints()
        return total, approx
    except Exception as exc:  # noqa: BLE001 - estimation is a best-effort convenience
        logger.warning("Could not pre-compute a progress total (%s); logging raw counts only", exc)
        return None, False


def start_generator(python: str, script: Path, seed: Path, work_dir: Path,
                     prefix: str, extra_args: list, log_path: Path,
                     logger: logging.Logger) -> subprocess.Popen:
    cmd = [python, str(script), str(seed), "--out-dir", str(work_dir), "--prefix", prefix] + extra_args
    log_file = open(log_path, "w", encoding="utf-8")
    print(f"[crack_runner] Starting generator: {' '.join(cmd)}")
    print(f"[crack_runner] Generator output logged to {log_path}")
    logger.debug("GEN CMD %s", " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=log_file, stderr=subprocess.STDOUT)
    logger.info("GEN START pid=%s", proc.pid)
    return proc


def resolve_hashcat(hashcat_bin: str, explicit_cwd: Optional[Path]) -> Tuple[str, Optional[Path]]:
    """Figure out the absolute hashcat executable path and, unless the
    caller pinned one, the directory to run it from.

    hashcat resolves ./OpenCL, ./modules, ./kernels etc. relative to its
    *current working directory* at launch, not relative to the executable
    itself. Portable hashcat distributions (the common case on Windows,
    and plenty of manual Linux installs) rely on always being launched
    from their own install folder; run them from anywhere else and they
    fail with e.g. "./OpenCL/: No such file or directory". We avoid that
    by locating the executable, and if its folder looks like such an
    install (it contains OpenCL/ or modules/), using that folder as the
    subprocess cwd -- with the executable and every path passed to it
    made absolute first, so it doesn't matter that we're no longer
    launching from the caller's own working directory."""
    if explicit_cwd is not None:
        which_result = shutil.which(hashcat_bin)
        exe = Path(which_result) if which_result else Path(hashcat_bin)
        return str(exe.resolve() if exe.exists() else exe), explicit_cwd

    which_result = shutil.which(hashcat_bin)
    exe_path = Path(which_result) if which_result else Path(hashcat_bin)
    if not exe_path.is_file():
        # Not found as a real file (e.g. relies on shell/PATH lookup we
        # can't resolve) -- leave it alone, same as before this fix.
        return hashcat_bin, None

    exe_path = exe_path.resolve()
    install_dir = exe_path.parent
    if (install_dir / "OpenCL").is_dir() or (install_dir / "modules").is_dir():
        return str(exe_path), install_dir
    return str(exe_path), None


def run_hashcat_attack(hashcat_exe: str, hashcat_cwd: Optional[Path], hash_type: int,
                        target: str, dict_path: Path, extra_args: list,
                        logger: logging.Logger) -> int:
    cmd = [hashcat_exe, "-a", "0", "-m", str(hash_type),
           str(Path(target).resolve()) if Path(target).exists() else target,
           str(dict_path.resolve())] + extra_args
    print(f"[crack_runner] Running: {' '.join(cmd)}" + (f"  (cwd={hashcat_cwd})" if hashcat_cwd else ""))
    logger.debug("HASHCAT CMD %s", " ".join(cmd))
    result = subprocess.run(cmd, cwd=hashcat_cwd)
    return result.returncode


def check_cracked(hashcat_exe: str, hashcat_cwd: Optional[Path], hash_type: int,
                   target: str, logger: logging.Logger) -> Optional[str]:
    """Ask hashcat what it has already cracked (via the potfile) for this
    target. Returns the raw --show output (one or more 'hash:...:plain'
    lines) if something is cracked, else None. Using --show instead of
    trusting the attack's own exit code makes this robust across hashcat
    versions and across resumed/aborted runs."""
    resolved_target = str(Path(target).resolve()) if Path(target).exists() else target
    cmd = [hashcat_exe, "-m", str(hash_type), "--show", resolved_target]
    logger.debug("SHOW CMD %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=hashcat_cwd)
    output = result.stdout.strip()
    return output if output else None


def safe_unlink(path: Path, logger: logging.Logger, retries: int = 5, delay: float = 0.3) -> bool:
    """Delete `path`, retrying briefly on a transient PermissionError.

    On Windows, a file that was just read (word-counted, handed to
    hashcat) can stay momentarily locked by Defender/AV real-time
    scanning or search indexing after the reading process has already
    exited -- os.unlink() then raises WinError 32 ("used by another
    process") even though nothing in this program still has it open.
    POSIX has no such failure mode, so this simply succeeds on the
    first try there. Returns True if the file is gone afterward, False
    if it still couldn't be removed after `retries` attempts -- in
    which case a warning is logged and the caller carries on rather
    than crashing the whole run (deleting dictionaries is a
    disk-space optimization, not something correctness depends on)."""
    for attempt in range(1, retries + 1):
        try:
            path.unlink(missing_ok=True)
            return True
        except PermissionError as exc:
            if attempt == retries:
                logger.warning(
                    "FILE DELETE FAILED %s after %d attempt(s): %s", path.name, attempt, exc)
                return False
            time.sleep(delay)
    return False


def terminate(proc: subprocess.Popen, timeout: float = 10.0) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def check_resume_argv(argv: List[str], parser: argparse.ArgumentParser) -> None:
    """argparse alone can't express "this flag must be given alone" --
    enforce it by inspecting raw argv. Exits with an error if --resume is
    combined with anything else, since every original parameter is supposed
    to be replayed from the saved state rather than re-specified."""
    has_resume = any(a == "--resume" or a.startswith("--resume=") for a in argv)
    if not has_resume:
        return
    valid = (len(argv) == 2 and argv[0] == "--resume") or \
            (len(argv) == 1 and argv[0].startswith("--resume="))
    if not valid:
        parser.error(
            "--resume must be the only argument given -- every original parameter is "
            "replayed from the run's saved state, so it cannot be combined with anything else"
        )


def serializable_args(args: argparse.Namespace) -> dict:
    result = {}
    for key, value in vars(args).items():
        if key == "resume_path":
            continue
        if isinstance(value, Path):
            value = str(value)
        result[key] = value
    return result


def save_state(state_path: Path, state: dict) -> None:
    """Atomic write: a crash or Ctrl-C mid-write can never leave a
    corrupted/partial state.json behind."""
    tmp_path = state_path.with_suffix(state_path.suffix + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp_path, state_path)


def load_state(state_path: Path) -> dict:
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read state file {state_path}: {exc}") from exc


def resolve_state_path(resume_arg: Path) -> Tuple[Path, Path]:
    """--resume accepts either the work directory or the state.json file
    itself; return (state_path, work_dir) either way."""
    if resume_arg.is_dir():
        return resume_arg / STATE_FILENAME, resume_arg
    return resume_arg, resume_arg.parent


def init_fresh_run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> Tuple[Path, Path, dict]:
    """Set up a brand new work directory: copy the seed (and, if it's a
    file, the target) into it, and write the initial state.json. Returns
    (work_dir, state_path, state)."""
    if not args.seed.is_file():
        parser.error(f"Seed dictionary not found: {args.seed}")

    work_dir = args.work_dir or Path(f"hashcat_run_{int(time.time())}")
    work_dir.mkdir(parents=True, exist_ok=True)
    state_path = work_dir / STATE_FILENAME

    existing = discover_files(work_dir, args.prefix)
    if existing or state_path.is_file():
        if not args.force:
            reason = "a saved run state" if state_path.is_file() else \
                f"{len(existing)} file(s) matching prefix '{args.prefix}'"
            print(
                f"Error: {work_dir} already has {reason}. Pick an empty --work-dir / "
                f"different --prefix, or pass --force to wipe it and start fresh.",
                file=sys.stderr,
            )
            sys.exit(1)
        for path in existing.values():
            path.unlink()
        state_path.unlink(missing_ok=True)

    seed_local = work_dir / f"seed{args.seed.suffix}"
    shutil.copyfile(args.seed, seed_local)

    target_path = Path(args.target)
    target_is_file = target_path.is_file()
    target_filename = None
    target_literal = None
    if target_is_file:
        target_filename = f"target{target_path.suffix}" if target_path.suffix else "target"
        shutil.copyfile(target_path, work_dir / target_filename)
    else:
        target_literal = args.target

    now = time.time()
    state = {
        "version": 1,
        "created_at": now,
        "updated_at": now,
        "args": serializable_args(args),
        "seed_filename": seed_local.name,
        "target_is_file": target_is_file,
        "target_filename": target_filename,
        "target_literal": target_literal,
        "processed": [],
        "cumulative_words": 0,
        "cracked_output": None,
        "status": "running",
    }
    save_state(state_path, state)
    return work_dir, state_path, state


def init_resume_run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> Tuple[Path, Path, dict]:
    """Load a previous run's state.json and rehydrate `args` from it (every
    task parameter comes from the saved state; args.python/dict_gen_script
    are deliberately left untouched -- they're re-resolved fresh below as
    the "installed program", not part of the portable run folder). Returns
    (work_dir, state_path, state)."""
    state_path, work_dir = resolve_state_path(args.resume_path)
    if not state_path.is_file():
        parser.error(
            f"No {STATE_FILENAME} found at {args.resume_path} -- not a hashcat_run "
            f"directory/state file"
        )
    try:
        state = load_state(state_path)
    except RuntimeError as exc:
        parser.error(str(exc))

    if state.get("cracked_output"):
        print("[crack_runner] This run already found the password:")
        print(state["cracked_output"])
        sys.exit(0)

    seed_local = work_dir / state["seed_filename"]
    if not seed_local.is_file():
        parser.error(
            f"{work_dir} is missing its seed copy ({state['seed_filename']}) -- "
            f"the hashcat_run folder is incomplete, cannot resume"
        )
    if state["target_is_file"]:
        target_local = work_dir / state["target_filename"]
        if not target_local.is_file():
            parser.error(
                f"{work_dir} is missing its target copy ({state['target_filename']}) -- "
                f"the hashcat_run folder is incomplete, cannot resume"
            )
        target = str(target_local)
    else:
        target = state["target_literal"]

    saved = state["args"]
    args.seed = seed_local
    args.target = target
    args.hash_type = saved["hash_type"]
    args.prefix = saved["prefix"]
    args.dictgen_args = saved["dictgen_args"]
    args.hashcat_args = saved["hashcat_args"]
    args.performance = saved["performance"]
    args.workload = saved["workload"]
    args.poll_interval = saved["poll_interval"]
    args.keep_dictionaries = saved["keep_dictionaries"]
    args.hashcat_bin = saved["hashcat_bin"]
    args.hashcat_cwd = Path(saved["hashcat_cwd"]) if saved["hashcat_cwd"] else None
    args.log_level = saved["log_level"]
    args.log_max_bytes = saved["log_max_bytes"]
    args.log_backups = saved["log_backups"]
    args.log_file = Path(saved["log_file"]) if saved["log_file"] else None
    args.work_dir = work_dir
    args.force = False

    return work_dir, state_path, state


def main() -> int:
    parser = build_arg_parser()
    check_resume_argv(sys.argv[1:], parser)
    args = parser.parse_args()

    if args.resume_path is None:
        missing = [name for name, val in (
            ("seed", args.seed), ("target", args.target), ("-m/--hash-type", args.hash_type),
        ) if val is None]
        if missing:
            parser.error(f"the following arguments are required: {', '.join(missing)}")

    if args.poll_interval <= 0:
        parser.error("--poll-interval must be > 0")

    try:
        dict_gen_script = resolve_dict_gen_script(args.dict_gen_script)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    resuming = args.resume_path is not None
    if resuming:
        work_dir, state_path, state = init_resume_run(args, parser)
        print(f"[crack_runner] Resuming run in {work_dir} "
              f"({len(state['processed'])} file(s) already processed)")
    else:
        work_dir, state_path, state = init_fresh_run(args, parser)

    dictgen_extra = shlex.split(args.dictgen_args)
    performance_flags = ["--force", "-O", "-w", str(args.workload)] if args.performance else []
    hashcat_extra = performance_flags + shlex.split(args.hashcat_args)
    if args.performance:
        print(f"[crack_runner] Performance mode: hashcat gets {' '.join(performance_flags)} "
              f"(plus any --hashcat-args, which take precedence on conflicts)")

    log_path = args.log_file or (work_dir / "crack_runner.log")
    logger = setup_logger(log_path, args.log_level, args.log_max_bytes, args.log_backups)
    print(f"[crack_runner] Run history logged to {log_path} (level {args.log_level})")
    if resuming:
        logger.info("RESUME state=%s processed=%d", state_path, len(state["processed"]))
    else:
        logger.info("START config=%s", vars(args))

    hashcat_exe, hashcat_cwd = resolve_hashcat(args.hashcat_bin, args.hashcat_cwd)
    if hashcat_cwd:
        print(f"[crack_runner] Running hashcat from {hashcat_cwd} (portable install detected)")
        logger.info("HASHCAT CWD %s", hashcat_cwd)

    total_estimate, approx = estimate_progress_total(
        dict_gen_script, args.seed, dictgen_extra, logger)
    if total_estimate:
        logger.info("ESTIMATE total_words=%s approx=%s", f"{total_estimate:,}", approx)

    processed: set = set(state["processed"])
    skipped_cleanup: set = set()
    cracked_output: Optional[str] = state.get("cracked_output")
    exit_code = 1
    cumulative_words = state["cumulative_words"]

    # Files already attacked in a prior invocation are deleted as soon as
    # hashcat is done with them (see the main loop below), so on --resume
    # there is nothing left on disk for dict_gen.py's own --resume to
    # detect. Tell it explicitly how many words and files that was instead,
    # via --skip-count/--start-index, so generation picks up right after
    # them -- deterministic, so this reproduces the exact same words dict_gen
    # would have produced there -- instead of restarting file numbering (and
    # writing/discarding already-tried words) from out-1.txt every time.
    resume_dictgen_args = []
    if processed:
        resume_dictgen_args = ["--skip-count", str(cumulative_words), "--start-index", str(max(processed))]

    # Clear any *unprocessed* dictionary files still on disk from a
    # previous, now-dead generator process before starting a new one.
    # dict_gen.py writes ahead of what hashcat has consumed, so an
    # interrupted run can leave files *beyond* the one actually being
    # attacked at the time (e.g. hashcat is still working on out-4.txt
    # while the generator has already raced ahead and started out-5.txt).
    # Left in place, such a stale higher-index file would satisfy the
    # "next file exists" readiness check below for the file the new
    # generator is still writing, handing it to hashcat mid-write and
    # silently skipping every word not yet generated at that moment.
    # Only indices NOT in `processed` are touched -- a file for an index
    # already confirmed fully attacked is left alone, so --keep-dictionaries
    # still gets to keep it instead of having it wiped on every --resume.
    stale = {i: p for i, p in discover_files(work_dir, args.prefix).items() if i not in processed}
    for path in stale.values():
        safe_unlink(path, logger)
    if stale:
        logger.info("FILES CLEARED (stale, pre-generator-start) count=%d", len(stale))

    generator = start_generator(
        args.python, dict_gen_script, args.seed, work_dir, args.prefix,
        dictgen_extra + resume_dictgen_args, work_dir / "dictgen.log", logger,
    )

    def progress_suffix() -> str:
        if not total_estimate:
            return ""
        pct = min(cumulative_words / total_estimate * 100, 100.0)
        return f" cumulative={cumulative_words:,}/{total_estimate:,} ({pct:.1f}%{'~' if approx else ''})"

    def persist_state(status: str) -> None:
        state["processed"] = sorted(processed)
        state["cumulative_words"] = cumulative_words
        state["cracked_output"] = cracked_output
        state["status"] = status
        state["updated_at"] = time.time()
        save_state(state_path, state)

    try:
        while True:
            files = discover_files(work_dir, args.prefix)
            generator_done = generator.poll() is not None

            # dict_gen.py always restarts numbering from 1, so after
            # --resume it will deterministically regenerate files already
            # tried in a previous invocation. Recognize and clean those up
            # without wasting a hashcat run on them.
            for i in sorted(files):
                if i in processed and i not in skipped_cleanup:
                    if not args.keep_dictionaries:
                        if safe_unlink(files[i], logger):
                            logger.info("FILE SKIPPED (already processed) %s", files[i].name)
                    skipped_cleanup.add(i)

            if generator_done:
                ready = sorted(i for i in files if i not in processed and i not in skipped_cleanup)
            else:
                ready = sorted(
                    i for i in files
                    if i not in processed and i not in skipped_cleanup and (i + 1) in files
                )

            for i in ready:
                path = files[i]
                word_count = sum(1 for _ in open(path, "r", encoding="utf-8", errors="replace"))
                print(f"[crack_runner] --- {path.name} ({word_count:,} words) ---")
                logger.info("FILE TAKEN %s words=%d", path.name, word_count)

                rc = run_hashcat_attack(
                    hashcat_exe, hashcat_cwd, args.hash_type, args.target, path,
                    hashcat_extra, logger)
                if rc not in (0, 1):
                    msg = (f"hashcat exited with unexpected status {rc} on {path.name} -- "
                           f"stopping (this usually means a configuration error, not just "
                           f"'not found in this file').")
                    print(f"[crack_runner] {msg}", file=sys.stderr)
                    logger.error("HASHCAT ERROR %s rc=%d", path.name, rc)
                    terminate(generator)
                    logger.info("GEN STOP reason=hashcat_error")
                    persist_state("error")
                    return 1

                processed.add(i)
                cumulative_words += word_count
                cracked_output = check_cracked(
                    hashcat_exe, hashcat_cwd, args.hash_type, args.target, logger)
                logger.info(
                    "FILE DONE %s words=%d rc=%d cracked=%s%s",
                    path.name, word_count, rc, bool(cracked_output), progress_suffix(),
                )

                if not args.keep_dictionaries:
                    if safe_unlink(path, logger):
                        logger.info("FILE DELETED %s", path.name)

                persist_state("cracked" if cracked_output else "running")

                if cracked_output:
                    break

            if cracked_output:
                exit_code = 0
                break

            if generator_done and all(i in processed for i in files):
                break

            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        print("\n[crack_runner] Interrupted, stopping...", file=sys.stderr)
        logger.warning("INTERRUPTED by user after %d file(s)%s", len(processed), progress_suffix())
        exit_code = 130
        persist_state("interrupted")
    finally:
        terminate(generator)
        logger.info("GEN STOP")

    if cracked_output:
        print("\n[crack_runner] CRACKED:")
        print(cracked_output)
        logger.info("CRACKED %s", cracked_output.replace("\n", " | "))
        if not args.keep_dictionaries:
            # The generator may have produced further files in the background
            # while the last hashcat run was in progress; they were never
            # tried, so there's no reason to leave them on disk.
            leftovers = discover_files(work_dir, args.prefix)
            deleted = sum(1 for path in leftovers.values() if safe_unlink(path, logger))
            if deleted:
                logger.info("FILES DELETED (unprocessed leftovers) count=%d", deleted)
        persist_state("cracked")
    elif exit_code == 1:
        print("\n[crack_runner] Exhausted all generated dictionaries without cracking the hash.")
        logger.info("EXHAUSTED files=%d%s", len(processed), progress_suffix())
        persist_state("exhausted")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
