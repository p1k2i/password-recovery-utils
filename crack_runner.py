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
        --hashcat-args "--force -O -w 3"
"""

import argparse
import logging
import re
import shlex
import shutil
import subprocess
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, Optional, Tuple

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a brute-force dictionary with dict_gen.py and feed it to "
                    "hashcat file by file, stopping as soon as the hash is cracked."
    )
    parser.add_argument("seed", type=Path,
                        help="Seed dictionary file passed to dict_gen.py (.txt or .json)")
    parser.add_argument("target",
                        help="What hashcat should attack: a hash string, or a path to a "
                             "file containing hash(es)")
    parser.add_argument("-m", "--hash-type", type=int, required=True,
                        help="hashcat -m hash type")
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


def terminate(proc: subprocess.Popen, timeout: float = 10.0) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def main() -> int:
    args = build_arg_parser().parse_args()
    parser = build_arg_parser()

    if args.poll_interval <= 0:
        parser.error("--poll-interval must be > 0")
    if not args.seed.is_file():
        parser.error(f"Seed dictionary not found: {args.seed}")

    try:
        dict_gen_script = resolve_dict_gen_script(args.dict_gen_script)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    work_dir = args.work_dir or Path(f"hashcat_run_{int(time.time())}")
    work_dir.mkdir(parents=True, exist_ok=True)

    existing = discover_files(work_dir, args.prefix)
    if existing:
        if not args.force:
            print(
                f"Error: {work_dir} already has {len(existing)} file(s) matching prefix "
                f"'{args.prefix}'. Pick an empty --work-dir / different --prefix, or pass --force "
                f"to delete them and start fresh.",
                file=sys.stderr,
            )
            return 1
        for path in existing.values():
            path.unlink()

    dictgen_extra = shlex.split(args.dictgen_args)
    hashcat_extra = shlex.split(args.hashcat_args)

    log_path = args.log_file or (work_dir / "crack_runner.log")
    logger = setup_logger(log_path, args.log_level, args.log_max_bytes, args.log_backups)
    print(f"[crack_runner] Run history logged to {log_path} (level {args.log_level})")
    logger.info("START config=%s", vars(args))

    hashcat_exe, hashcat_cwd = resolve_hashcat(args.hashcat_bin, args.hashcat_cwd)
    if hashcat_cwd:
        print(f"[crack_runner] Running hashcat from {hashcat_cwd} (portable install detected)")
        logger.info("HASHCAT CWD %s", hashcat_cwd)

    total_estimate, approx = estimate_progress_total(
        dict_gen_script, args.seed, dictgen_extra, logger)
    if total_estimate:
        logger.info("ESTIMATE total_words=%s approx=%s", f"{total_estimate:,}", approx)

    generator = start_generator(
        args.python, dict_gen_script, args.seed, work_dir, args.prefix,
        dictgen_extra, work_dir / "dictgen.log", logger,
    )

    processed: set = set()
    cracked_output: Optional[str] = None
    exit_code = 1
    cumulative_words = 0

    def progress_suffix() -> str:
        if not total_estimate:
            return ""
        pct = min(cumulative_words / total_estimate * 100, 100.0)
        return f" cumulative={cumulative_words:,}/{total_estimate:,} ({pct:.1f}%{'~' if approx else ''})"

    try:
        while True:
            files = discover_files(work_dir, args.prefix)
            generator_done = generator.poll() is not None

            if generator_done:
                ready = sorted(i for i in files if i not in processed)
            else:
                ready = sorted(i for i in files if i not in processed and (i + 1) in files)

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
                    path.unlink(missing_ok=True)
                    logger.info("FILE DELETED %s", path.name)

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
            for path in leftovers.values():
                path.unlink(missing_ok=True)
            if leftovers:
                logger.info("FILES DELETED (unprocessed leftovers) count=%d", len(leftovers))
    elif exit_code == 1:
        print("\n[crack_runner] Exhausted all generated dictionaries without cracking the hash.")
        logger.info("EXHAUSTED files=%d%s", len(processed), progress_suffix())

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
