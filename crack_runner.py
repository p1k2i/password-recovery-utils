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
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Optional


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
    return parser


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


def start_generator(python: str, script: Path, seed: Path, work_dir: Path,
                     prefix: str, extra_args: list, log_path: Path) -> subprocess.Popen:
    cmd = [python, str(script), str(seed), "--out-dir", str(work_dir), "--prefix", prefix] + extra_args
    log_file = open(log_path, "w", encoding="utf-8")
    print(f"[crack_runner] Starting generator: {' '.join(cmd)}")
    print(f"[crack_runner] Generator output logged to {log_path}")
    return subprocess.Popen(cmd, stdout=log_file, stderr=subprocess.STDOUT)


def run_hashcat_attack(hashcat_bin: str, hash_type: int, target: str,
                        dict_path: Path, extra_args: list) -> int:
    cmd = [hashcat_bin, "-a", "0", "-m", str(hash_type), target, str(dict_path)] + extra_args
    print(f"[crack_runner] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    return result.returncode


def check_cracked(hashcat_bin: str, hash_type: int, target: str) -> Optional[str]:
    """Ask hashcat what it has already cracked (via the potfile) for this
    target. Returns the raw --show output (one or more 'hash:...:plain'
    lines) if something is cracked, else None. Using --show instead of
    trusting the attack's own exit code makes this robust across hashcat
    versions and across resumed/aborted runs."""
    cmd = [hashcat_bin, "-m", str(hash_type), "--show", target]
    result = subprocess.run(cmd, capture_output=True, text=True)
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

    generator = start_generator(
        args.python, dict_gen_script, args.seed, work_dir, args.prefix,
        dictgen_extra, work_dir / "dictgen.log",
    )

    processed: set = set()
    cracked_output: Optional[str] = None
    exit_code = 1

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

                rc = run_hashcat_attack(
                    args.hashcat_bin, args.hash_type, args.target, path, hashcat_extra)
                if rc not in (0, 1):
                    print(
                        f"[crack_runner] hashcat exited with unexpected status {rc} on "
                        f"{path.name} -- stopping (this usually means a configuration error, "
                        f"not just 'not found in this file').",
                        file=sys.stderr,
                    )
                    terminate(generator)
                    return 1

                processed.add(i)
                cracked_output = check_cracked(args.hashcat_bin, args.hash_type, args.target)
                if not args.keep_dictionaries:
                    path.unlink(missing_ok=True)

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
        exit_code = 130
    finally:
        terminate(generator)

    if cracked_output:
        print("\n[crack_runner] CRACKED:")
        print(cracked_output)
        if not args.keep_dictionaries:
            # The generator may have produced further files in the background
            # while the last hashcat run was in progress; they were never
            # tried, so there's no reason to leave them on disk.
            for path in discover_files(work_dir, args.prefix).values():
                path.unlink(missing_ok=True)
    elif exit_code == 1:
        print("\n[crack_runner] Exhausted all generated dictionaries without cracking the hash.")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
