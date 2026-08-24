#!/usr/bin/env python3
"""
dict_gen.py - Password brute-force dictionary generator.

Takes a seed dictionary of "pieces" (fragments a password may be built
from) and generates every combination of pieces (concatenated together,
repetition allowed) whose resulting length satisfies the requested
min/max length. Every valid combination is written to disk; output is
split across multiple files (<prefix>-1.txt, <prefix>-2.txt, ...)
according to --split-size and/or --split-count.

The seed dictionary can be a plain text file (one piece per line) or a
JSON file (detected by the .json extension) that additionally defines
per-piece rules:

    {
      "pieces": [
        {"value": "admin", "positions": "first"},
        {"value": "2023", "requires": "admin"},
        {"value": "root", "repeatable": false},
        {"value": "!", "positions": "last"},
        {"value": "@", "positions": "last"},
        {"value": "#", "positions": ["first", 3]}
      ],
      "exclusive_groups": [
        ["!", "@", "#"]
      ],
      "requires": [
        {"if": "2023", "then": ["admin"]}
      ]
    }

  - A piece can be a bare string, or an object with "value" plus rules:
      "repeatable": false   -> the piece may be used at most once per word
      "max_repeat": N       -> the piece may be used at most N times per word
                                (overrides the global --max-repeat for this piece)
      "positions": ...      -> restricts which slot(s) in the piece sequence
                                this piece may occupy (see below)
  - "exclusive_groups": each group lists pieces that are mutually
    exclusive -- at most one piece per group may appear in a word
    ("or this or that").
  - "requires": each rule says that if the "if" piece appears in a word,
    every piece listed in "then" must also appear in it ("if this then
    that too"). "then" may be a single string or a list.

  "positions" restricts where a piece may sit in the sequence of pieces
  that makes up a word (1-based slot counting, not character index).
  Accepts a single value or a list of alternatives (any one matching is
  enough):
      1, 2, 3, ...  -> that exact slot ("1st and 3rd" -> [1, 3])
      "first"       -> same as 1
      "last"        -> the final piece in the word
      "middle"      -> any slot that is neither first nor last
      "any"         -> unrestricted (the default when "positions" is omitted)
  "last" and "middle" are evaluated against each word's own length, since
  a word can end at many different lengths -- e.g. a piece restricted to
  "last" is only allowed to close a word out, never to be followed by
  another piece.

Example:
    python dict_gen.py seed.txt --min-length 4 --max-length 8 \
        --prefix out --split-count 1000000 --max-repeat 3
    python dict_gen.py seed.json --min-length 4 --max-length 12 --prefix out

WARNING: the number of combinations grows combinatorially with
--max-length and the number of pieces. Choose --max-length and
--max-repeat carefully to keep the output bounded.
"""

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

PositionSpec = List[Union[int, str]]


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


class PieceRules:
    """Pieces plus the per-piece usage rules that constrain how they may
    be combined: an optional repeat-count override, mutual-exclusion
    groups, "if this piece is used, that piece must be used too"
    requirements, and a restriction on which slot(s) a piece may occupy
    within the sequence of pieces that makes up a word."""

    def __init__(self, pieces: List[str],
                 max_repeat_overrides: Dict[str, int],
                 exclusive_of: Dict[str, Set[str]],
                 requires: Dict[str, Set[str]],
                 position_rules: Dict[str, PositionSpec]):
        self.pieces = pieces
        self.max_repeat_overrides = max_repeat_overrides
        self.exclusive_of = exclusive_of
        self.requires = requires
        self.position_rules = position_rules

    def has_constraints(self) -> bool:
        return (bool(self.max_repeat_overrides) or any(self.exclusive_of.values())
                or any(self.requires.values()) or bool(self.position_rules))


def load_pieces_txt(path: Path) -> PieceRules:
    """Load unique, non-empty pieces from a plain-text dictionary file
    (one piece per line, no per-piece rules), preserving order."""
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
    return PieceRules(pieces, {}, {p: set() for p in pieces}, {p: set() for p in pieces}, {})


POSITION_KEYWORDS = ("first", "last", "middle", "any")


def parse_positions(value, piece_label: str) -> Optional[PositionSpec]:
    """Normalize a piece's 'positions' field into a list of tokens (ints
    and/or the keywords "first"/"last"/"middle"), or None for
    unrestricted. Accepts a single string/int or a list of them."""
    if value is None:
        return None
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        value = [value]
    if not isinstance(value, list) or not value:
        raise ValueError(
            f"piece {piece_label!r}: 'positions' must be an integer, one of "
            f"{POSITION_KEYWORDS}, or a non-empty list of these"
        )

    normalized: PositionSpec = []
    for token in value:
        if isinstance(token, bool) or not isinstance(token, (int, str)):
            raise ValueError(f"piece {piece_label!r}: invalid 'positions' entry {token!r}")
        if isinstance(token, int):
            if token <= 0:
                raise ValueError(
                    f"piece {piece_label!r}: position numbers are 1-based and must be >= 1, "
                    f"got {token}"
                )
            normalized.append(token)
            continue
        keyword = token.strip().lower()
        if keyword not in POSITION_KEYWORDS:
            raise ValueError(
                f"piece {piece_label!r}: unknown position {token!r} "
                f"(expected an integer or one of {POSITION_KEYWORDS})"
            )
        normalized.append(keyword)

    if "any" in normalized:
        if len(normalized) > 1:
            raise ValueError(
                f"piece {piece_label!r}: 'any' means unrestricted and cannot be combined "
                f"with other position constraints"
            )
        return None  # "any" is the same as omitting 'positions' entirely
    return normalized


def load_pieces_json(path: Path) -> PieceRules:
    """Load pieces and their usage rules from a JSON dictionary file.
    See the module docstring for the schema."""
    with open(path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {path}: {exc}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("pieces"), list):
        raise ValueError(f"{path}: top-level JSON must be an object with a 'pieces' array")

    pieces: List[str] = []
    seen: Set[str] = set()
    max_repeat_overrides: Dict[str, int] = {}
    position_rules: Dict[str, PositionSpec] = {}

    for i, item in enumerate(data["pieces"]):
        if isinstance(item, str):
            value, repeatable, max_repeat, positions = item, None, None, None
        elif isinstance(item, dict):
            value = item.get("value")
            if not isinstance(value, str) or value == "":
                raise ValueError(f"pieces[{i}]: 'value' must be a non-empty string")
            repeatable = item.get("repeatable")
            max_repeat = item.get("max_repeat")
            positions = item.get("positions")
            unknown = set(item) - {"value", "repeatable", "max_repeat", "positions"}
            if unknown:
                raise ValueError(f"pieces[{i}] ({value!r}): unknown key(s) {sorted(unknown)}")
        else:
            raise ValueError(f"pieces[{i}]: must be a string or an object with a 'value' key")

        if value == "":
            raise ValueError(f"pieces[{i}]: empty piece value is not allowed")
        if value in seen:
            raise ValueError(f"Duplicate piece value: {value!r}")
        seen.add(value)
        pieces.append(value)

        if repeatable is not None and max_repeat is not None:
            raise ValueError(f"piece {value!r}: specify either 'repeatable' or 'max_repeat', not both")
        if repeatable is False:
            max_repeat_overrides[value] = 1
        elif repeatable not in (None, True):
            raise ValueError(f"piece {value!r}: 'repeatable' must be true or false")
        elif max_repeat is not None:
            if not isinstance(max_repeat, int) or isinstance(max_repeat, bool) or max_repeat <= 0:
                raise ValueError(f"piece {value!r}: 'max_repeat' must be a positive integer")
            max_repeat_overrides[value] = max_repeat

        parsed_positions = parse_positions(positions, value)
        if parsed_positions is not None:
            position_rules[value] = parsed_positions

    if not pieces:
        raise ValueError(f"No pieces defined in {path}")

    known = set(pieces)
    exclusive_of: Dict[str, Set[str]] = {p: set() for p in pieces}
    for gi, group in enumerate(data.get("exclusive_groups", [])):
        if not isinstance(group, list) or len(group) < 2:
            raise ValueError(f"exclusive_groups[{gi}]: must be a list of 2 or more piece values")
        group_set = set()
        for v in group:
            if v not in known:
                raise ValueError(f"exclusive_groups[{gi}]: unknown piece {v!r}")
            group_set.add(v)
        for v in group_set:
            exclusive_of[v] |= (group_set - {v})

    requires: Dict[str, Set[str]] = {p: set() for p in pieces}
    for ri, rule in enumerate(data.get("requires", [])):
        if not isinstance(rule, dict) or "if" not in rule or "then" not in rule:
            raise ValueError(f"requires[{ri}]: must be an object with 'if' and 'then'")
        trigger = rule["if"]
        then = rule["then"]
        if isinstance(then, str):
            then = [then]
        if trigger not in known:
            raise ValueError(f"requires[{ri}]: unknown piece {trigger!r} in 'if'")
        if not isinstance(then, list) or not then:
            raise ValueError(f"requires[{ri}]: 'then' must be a non-empty string or list of strings")
        for t in then:
            if t not in known:
                raise ValueError(f"requires[{ri}]: unknown piece {t!r} in 'then'")
            if t == trigger:
                raise ValueError(f"requires[{ri}]: piece {trigger!r} cannot require itself")
            requires[trigger].add(t)

    for p in pieces:
        conflict = requires[p] & exclusive_of[p]
        if conflict:
            raise ValueError(
                f"Contradictory rules: {p!r} requires {sorted(conflict)} but is also mutually "
                f"exclusive with {sorted(conflict)} -- no word could ever satisfy both rules"
            )

    return PieceRules(pieces, max_repeat_overrides, exclusive_of, requires, position_rules)


def load_dictionary(path: Path) -> PieceRules:
    """Load the seed dictionary, dispatching on file extension: '.json'
    files use the rule-aware JSON schema, anything else is treated as a
    plain one-piece-per-line text file."""
    if path.suffix.lower() == ".json":
        return load_pieces_json(path)
    return load_pieces_txt(path)


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


def _position_spec_is_static(spec: PositionSpec) -> bool:
    """True if every token in a position spec is decidable from the
    piece's own slot index alone (an exact slot number, or "first"),
    with none depending on the eventual total sequence length ("last",
    "middle")."""
    return all(token != "last" and token != "middle" for token in spec)


def _position_matches(spec: PositionSpec, index0: int, total: int) -> bool:
    """Does a piece placed at 0-based `index0` within a `total`-piece
    sequence satisfy its position spec?"""
    for token in spec:
        if token == "first":
            if index0 == 0:
                return True
        elif token == "last":
            if index0 == total - 1:
                return True
        elif token == "middle":
            if 0 < index0 < total - 1:
                return True
        elif isinstance(token, int):
            if index0 == token - 1:
                return True
    return False


def generate(rules: PieceRules, min_length: int, max_length: int,
             global_max_repeat: Optional[int], writer: OutputWriter,
             progress: "ProgressReporter") -> None:
    """DFS over sequences of pieces (repetition allowed, subject to each
    piece's rules). Every intermediate concatenation whose length is
    within [min_length, max_length], whose used pieces satisfy all
    "requires" rules, and whose pieces sit in slots their "positions"
    rule allows for that word's own length, is written out as a
    candidate password. Recursion always terminates because every piece
    has length >= 1, so the current length strictly grows with each
    appended piece."""

    pieces = rules.pieces
    min_piece_len = min(len(p) for p in pieces)
    usage_counts: Dict[str, int] = {}
    sequence: List[str] = []

    def repeat_limit(piece: str) -> Optional[int]:
        return rules.max_repeat_overrides.get(piece, global_max_repeat)

    def requirements_satisfied() -> bool:
        for used_piece in usage_counts:
            for required in rules.requires.get(used_piece, ()):
                if usage_counts.get(required, 0) <= 0:
                    return False
        return True

    def positions_satisfied() -> bool:
        if not rules.position_rules:
            return True
        total = len(sequence)
        for index0, piece in enumerate(sequence):
            spec = rules.position_rules.get(piece)
            if spec is not None and not _position_matches(spec, index0, total):
                return False
        return True

    def can_place_at(piece: str, index0: int) -> bool:
        """Cheap early rejection for slot assignments a piece's position
        rule can never satisfy, regardless of how the word continues
        from here. Only applies when the rule is fully static (no
        "last"/"middle", which depend on the word's eventual length and
        so can only be checked once a candidate word is complete)."""
        spec = rules.position_rules.get(piece)
        if spec is None or not _position_spec_is_static(spec):
            return True
        return _position_matches(spec, index0, index0 + 1)

    def recurse(current: str, current_len: int) -> None:
        if (current and min_length <= current_len <= max_length
                and requirements_satisfied() and positions_satisfied()):
            writer.write(current)
            progress.update(writer)
        if current_len + min_piece_len > max_length:
            return
        next_index0 = len(sequence)
        for piece in pieces:
            limit = repeat_limit(piece)
            if limit is not None and usage_counts.get(piece, 0) >= limit:
                continue
            if any(usage_counts.get(other, 0) > 0 for other in rules.exclusive_of.get(piece, ())):
                continue
            if not can_place_at(piece, next_index0):
                continue
            usage_counts[piece] = usage_counts.get(piece, 0) + 1
            sequence.append(piece)
            recurse(current + piece, current_len + len(piece))
            sequence.pop()
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
        help="Path to the seed dictionary: a .txt file (one piece per line) "
             "or a .json file with per-piece rules (see module docstring)")
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
        rules = load_dictionary(args.dictionary)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    args.out_dir.mkdir(parents=True, exist_ok=True)

    total_estimate = estimate_total(rules.pieces, args.min_length, args.max_length)
    approx = args.max_repeat is not None or rules.has_constraints()
    progress = ProgressReporter(total_estimate, approx=approx, enabled=not args.quiet)

    writer = OutputWriter(args.out_dir, args.prefix, args.split_size, args.split_count)
    try:
        generate(rules, args.min_length, args.max_length, args.max_repeat, writer, progress)
    finally:
        progress.finish(writer)
        writer.close()

    print(
        f"Done. {writer.total_written} words written across {writer.file_index} file(s).",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
