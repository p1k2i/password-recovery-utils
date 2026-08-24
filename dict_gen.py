#!/usr/bin/env python3
"""
dict_gen.py - Password brute-force dictionary generator.

Takes a seed dictionary of "pieces" (fragments a password may be built
from) and generates every combination of pieces (concatenated together,
repetition allowed) whose resulting length satisfies the requested
min/max length. Every valid combination is written to disk; output is
split across multiple files (<prefix>-1.txt, <prefix>-2.txt, ...)
according to --split-size and/or --split-count.

Example:
    python dict_gen.py seed.txt --min-length 4 --max-length 8 \
        --prefix out --split-count 1000000 --max-repeat 3

WARNING: the number of combinations grows combinatorially with
--max-length and the number of pieces. Choose --max-length and
--max-repeat carefully to keep the output bounded.
"""

import argparse
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Optional


def parse_size(value: str) -> int:
    """Parse a human-readable size string ('10MB', '500K', '2GiB', or a
    plain number of bytes) into an integer number of bytes."""
    value = value.strip()
    units = {
        "": 1,
        "B": 1,
        "K": 1024, "KB": 1024, "KIB": 1024,
        "M": 1024 ** 2, "MB": 1024 ** 2, "MIB": 1024 ** 2,
        "G": 1024 ** 3, "GB": 1024 ** 3, "GIB": 1024 ** 3,
    }
    split_at = len(value)
    while split_at > 0 and not value[split_at - 1].isdigit():
        split_at -= 1
    number, unit = value[:split_at], value[split_at:].strip().upper()
    if unit not in units:
        raise argparse.ArgumentTypeError(f"Unknown size unit {unit!r} in {value!r}")
    try:
        return int(float(number) * units[unit])
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid size value: {value!r}")


def load_pieces(path: Path) -> list:
    """Load unique, non-empty pieces from the seed dictionary file,
    preserving their original order."""
    pieces = []
    seen = set()
    with open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
            piece = raw_line.rstrip("\r\n")
            if not piece or piece in seen:
                continue
            seen.add(piece)
            pieces.append(piece)
    if not pieces:
        raise ValueError(f"No usable pieces found in dictionary file: {path}")
    return pieces


class OutputWriter:
    """Streams generated words to <prefix>-N.txt files, rolling over to
    a new file whenever the active size and/or word-count limit is hit."""

    def __init__(self, out_dir: Path, prefix: str,
                 split_size: Optional[int], split_count: Optional[int]):
        self.out_dir = out_dir
        self.prefix = prefix
        self.split_size = split_size
        self.split_count = split_count
        self.file_index = 0
        self.current_file = None
        self.current_path = None
        self.current_size = 0
        self.current_count = 0
        self.total_written = 0
        self._open_next_file()

    def _open_next_file(self) -> Path:
        if self.current_file is not None:
            self.current_file.close()
        self.file_index += 1
        path = self.out_dir / f"{self.prefix}-{self.file_index}.txt"
        self.current_file = open(path, "w", encoding="utf-8")
        self.current_path = path
        self.current_size = 0
        self.current_count = 0
        return path

    def write(self, word: str) -> None:
        line = word + "\n"
        line_bytes = len(line.encode("utf-8"))

        if self.current_count > 0 and (
            (self.split_size is not None and self.current_size + line_bytes > self.split_size)
            or (self.split_count is not None and self.current_count >= self.split_count)
        ):
            self._open_next_file()

        self.current_file.write(line)
        self.current_size += line_bytes
        self.current_count += 1
        self.total_written += 1

    def close(self) -> None:
        if self.current_file is not None:
            self.current_file.close()
            self.current_file = None


def estimate_total(pieces, min_length: int, max_length: int) -> int:
    """Count how many non-empty piece-sequences produce a length within
    [min_length, max_length], ignoring --max-repeat. This is an exact
    count when --max-repeat is not used, and an upper bound otherwise
    (repeat limits can only reduce the real output)."""
    lengths = [len(p) for p in pieces]
    counts = [0] * (max_length + 1)
    counts[0] = 1
    for length in range(1, max_length + 1):
        counts[length] = sum(counts[length - plen] for plen in lengths if plen <= length)
    return sum(counts[max(min_length, 1):max_length + 1])


def fmt_duration(seconds: float) -> str:
    if seconds < 0 or seconds == float("inf"):
        return "--:--:--"
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def fmt_bytes(num_bytes: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if num_bytes < 1024 or unit == "GB":
            return f"{num_bytes:.1f} {unit}" if unit != "B" else f"{int(num_bytes)} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} GB"


def _enable_windows_vt_mode() -> bool:
    """Try to turn on ANSI/VT escape processing for stderr on Windows
    (Windows 10+ supports it, but legacy conhost windows have it off by
    default). Returns True if escape sequences can be used afterwards."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        STD_ERROR_HANDLE = -12
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(STD_ERROR_HANDLE)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        if not kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING):
            return False
        return True
    except Exception:
        return False


class ProgressReporter:
    """Renders an in-place-updating progress display on stderr, the way
    unix tools like wget/pip do (overwriting the same spot instead of
    scrolling the console). Uses a 3-line ANSI display when the terminal
    supports cursor movement (any unix tty, or Windows 10+ with VT
    processing enabled); falls back to a single carriage-return-updated
    line on terminals that don't (e.g. legacy Windows cmd.exe). Disabled
    entirely when stderr isn't a terminal, or via --quiet."""

    BAR_WIDTH = 30
    MIN_INTERVAL = 0.15  # seconds between redraws, to keep overhead low

    def __init__(self, total_estimate: int, approx: bool, enabled: bool):
        self.total_estimate = max(total_estimate, 1)
        self.approx = approx
        self.start_time = time.monotonic()
        self._last_draw = 0.0
        self._drawn_once = False

        is_tty = enabled and sys.stderr.isatty()
        if not is_tty:
            self.mode = "off"
        elif _enable_windows_vt_mode():
            self.mode = "ansi"
        else:
            self.mode = "line"

    def update(self, writer: "OutputWriter", force: bool = False) -> None:
        if self.mode == "off":
            return
        now = time.monotonic()
        if not force and (now - self._last_draw) < self.MIN_INTERVAL:
            return
        self._last_draw = now

        written = writer.total_written
        elapsed = now - self.start_time
        fraction = min(written / self.total_estimate, 1.0)
        rate = written / elapsed if elapsed > 0 else 0.0
        remaining = max(self.total_estimate - written, 0)
        eta = remaining / rate if rate > 0 else float("inf")
        mark = "~" if self.approx else ""

        filled = int(self.BAR_WIDTH * fraction)
        bar = "#" * filled + "-" * (self.BAR_WIDTH - filled)

        if self.mode == "ansi":
            line1 = f"[{bar}] {fraction * 100:5.1f}%{mark}  {written:,} / {self.total_estimate:,} words"
            line2 = (f"Elapsed {fmt_duration(elapsed)}  ETA {fmt_duration(eta)}{mark}  "
                     f"Rate {rate:,.0f} words/s")
            line3 = (f"File {writer.current_path.name}  ({writer.file_index} written)  "
                     f"{fmt_bytes(writer.current_size)}  {writer.current_count:,} words in file")

            out = sys.stderr
            if self._drawn_once:
                out.write("\033[3F")
            self._drawn_once = True
            out.write(f"\033[K{line1}\n\033[K{line2}\n\033[K{line3}\n")
            out.flush()
        else:  # single-line carriage-return fallback
            text = (f"[{bar}] {fraction * 100:5.1f}%{mark} {written:,}/{self.total_estimate:,} "
                    f"ETA {fmt_duration(eta)}{mark} {rate:,.0f}/s {writer.current_path.name}")
            width = shutil.get_terminal_size(fallback=(100, 24)).columns
            text = text[:width - 1].ljust(width - 1)
            self._drawn_once = True
            sys.stderr.write("\r" + text)
            sys.stderr.flush()

    def finish(self, writer: "OutputWriter") -> None:
        if self.mode == "off":
            return
        self.update(writer, force=True)
        if self.mode == "line" and self._drawn_once:
            sys.stderr.write("\n")
            sys.stderr.flush()


def generate(pieces, min_length: int, max_length: int,
             max_repeat: Optional[int], writer: OutputWriter,
             progress: "ProgressReporter") -> None:
    """DFS over sequences of pieces (repetition allowed). Every
    intermediate concatenation whose length is within
    [min_length, max_length] is written out as a candidate password.
    Recursion always terminates because every piece has length >= 1,
    so the current length strictly grows with each appended piece."""

    min_piece_len = min(len(p) for p in pieces)
    usage_counts = {}

    def recurse(current: str, current_len: int) -> None:
        if current and min_length <= current_len <= max_length:
            writer.write(current)
            progress.update(writer)
        if current_len + min_piece_len > max_length:
            return
        for piece in pieces:
            if max_repeat is not None:
                if usage_counts.get(piece, 0) >= max_repeat:
                    continue
                usage_counts[piece] = usage_counts.get(piece, 0) + 1
            recurse(current + piece, current_len + len(piece))
            if max_repeat is not None:
                usage_counts[piece] -= 1
                if usage_counts[piece] == 0:
                    del usage_counts[piece]

    recurse("", 0)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a brute-force password dictionary by combining "
                     "pieces from a seed dictionary file."
    )
    parser.add_argument(
        "dictionary", type=Path,
        help="Path to the seed dictionary file (one piece per line)")
    parser.add_argument(
        "--min-length", type=int, default=0,
        help="Minimum output word length (default: 0)")
    parser.add_argument(
        "--max-length", type=int, default=32,
        help="Maximum output word length (default: 32)")
    parser.add_argument(
        "--prefix", type=str, default="dict",
        help="Prefix for output files (default: 'dict')")
    parser.add_argument(
        "--out-dir", type=Path, default=Path("."),
        help="Directory to write output files into (default: current directory)")
    parser.add_argument(
        "--split-size", type=parse_size, default=None,
        help="Split output files by size, e.g. '10MB', '500K', '2GiB'")
    parser.add_argument(
        "--split-count", type=int, default=None,
        help="Split output files by number of words per file")
    parser.add_argument(
        "--max-repeat", type=int, default=None,
        help="Maximum number of times a single piece may repeat within one generated word")
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress the live progress display")
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()

    parser = build_arg_parser()
    if args.min_length < 0:
        parser.error("--min-length must be >= 0")
    if args.max_length < args.min_length:
        parser.error("--max-length must be >= --min-length")
    if args.split_count is not None and args.split_count <= 0:
        parser.error("--split-count must be > 0")
    if args.split_size is not None and args.split_size <= 0:
        parser.error("--split-size must be > 0")
    if args.max_repeat is not None and args.max_repeat <= 0:
        parser.error("--max-repeat must be > 0")

    try:
        pieces = load_pieces(args.dictionary)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    args.out_dir.mkdir(parents=True, exist_ok=True)

    total_estimate = estimate_total(pieces, args.min_length, args.max_length)
    progress = ProgressReporter(
        total_estimate, approx=args.max_repeat is not None, enabled=not args.quiet)

    writer = OutputWriter(args.out_dir, args.prefix, args.split_size, args.split_count)
    try:
        generate(pieces, args.min_length, args.max_length, args.max_repeat, writer, progress)
    finally:
        progress.finish(writer)
        writer.close()

    print(
        f"Done. {writer.total_written} words written across {writer.file_index} file(s).",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
