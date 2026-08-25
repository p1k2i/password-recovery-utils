# Password Recovery Utils

A sophisticated password recovery toolkit for RAR archives and other hashcat-supported formats. This project combines intelligent dictionary generation with hashcat's cracking power to efficiently recover lost passwords.

## Overview

**password-recovery-utils** is a two-stage password recovery system:

1. **dict_gen.py** — Generates candidate password dictionaries from seed pieces with complex constraint rules
2. **crack_runner.py** — Orchestrates hashcat attacks, feeding dictionaries file-by-file and stopping at first success

The system efficiently handles massive wordlists by streaming output into multiple files and processing them on-demand, minimizing disk usage and maximizing throughput.

## Key Features

### Dictionary Generation (dict_gen.py)

- **Piece-based composition**: Build passwords from fragments (pieces) rather than brute-forcing individual characters
- **Powerful constraint rules**:
  - **Position rules**: Force pieces to specific slots (first, last, middle, or numbered positions)
  - **Mutual exclusion**: Define groups where at most one piece may appear per password
  - **Requirements**: "If piece A is used, piece B must also be used"
  - **Relations**: Control how pieces sit relative to each other (together, separate, ordered)
  - **Per-piece repeat limits**: Override global max-repeat for specific pieces
- **Large-scale output**: Split generated dictionaries by size or word count to manage disk space
- **Live progress tracking**: Real-time progress bar with Windows cmd.exe fallback (no ANSI requirement)
- **Resume functionality**: Detect existing output files, skip already-written words, and continue generation seamlessly
- **JSON seed format**: Full rule support via schema-driven JSON configuration
- **Plain text seeds**: Simple one-piece-per-line format for basic use cases

### Cracking Orchestration (crack_runner.py)

- **Streaming generation**: Starts dictionary generation in the background while hashcat runs
- **File-by-file processing**: Each generated file is processed only after generation completes (no partial reads)
- **Early exit**: Stops immediately when password is cracked, terminating the generator
- **Synchronized resume**: Both dict_gen.py and crack_runner.py support `--resume` for seamless recovery from interruptions—continue exactly where you left off across power failures, timeouts, or manual stops
- **Robust hashcat integration**:
  - Auto-detects portable hashcat installations
  - Handles working directory configuration for OpenCL/modules lookup
  - Verifies success via `hashcat --show` to handle resumed/aborted runs
- **Comprehensive logging**: Rotating log files track every step (start, file taken, processing, results)
- **Progress estimation**: Pre-computes expected output count for percentage tracking
- **Configurable attacks**: Pass any hashcat arguments, hash types, and attack modes

## Installation

### Requirements

- **Python 3.7+**
- **hashcat** (installed and in PATH, or specify with `--hashcat-bin`)
  - For portable installations, place it in a folder with `OpenCL/` or `modules/` subdirectories
- **For RAR files**: Ensure hashcat is compiled with RAR support (hashcat mode 13000 for RAR5, 23800 for RAR4)

### Setup

Clone or download this repository:

```bash
git clone <repository-url>
cd password-recovery-utils
```

No additional Python dependencies are required—the project uses only the standard library.

## Usage

### Basic Example

Recover a RAR5 archive password using a JSON seed:

```bash
python crack_runner.py seed.json file.rar.hash -m 13000 \
    --work-dir ./recovery_run \
    --dictgen-args "--min-length 12 --max-length 32"
```

### Resume Interrupted Recovery

If a recovery is interrupted (power failure, timeout, or manual stop), resume from where it left off:

```bash
# Original command was interrupted
python crack_runner.py seed.json file.rar.hash -m 13000 \
    --work-dir ./recovery_run \
    --dictgen-args "--min-length 12 --max-length 32"

# Resume: dict_gen.py automatically skips written words, crack_runner continues from next file
python crack_runner.py seed.json file.rar.hash -m 13000 \
    --work-dir ./recovery_run \
    --prefix dict \
    --dictgen-args "--min-length 12 --max-length 32 --resume"
```

Both scripts automatically detect existing files and synchronize seamlessly—no manual cleanup needed.

### Generating Dictionaries Only

To generate a dictionary without running hashcat:

```bash
python dict_gen.py seed.txt \
    --out-dir ./dictionaries \
    --min-length 4 \
    --max-length 10 \
    --split-size 100MB
```

### Dictionary Generation with Rules

Use a JSON seed file with advanced constraints:

```bash
python dict_gen.py seed.json \
    --min-length 8 \
    --max-length 20 \
    --split-count 5000000 \
    --max-repeat 2
```

### Performance Mode (GPU Optimization)

For maximum GPU speed, use the `--performance` flag to automatically apply hashcat's speed-oriented settings:

```bash
python crack_runner.py seed.json file.rar.hash -m 13000 \
    --performance \
    --workload 3 \
    --work-dir ./fast_recovery
```

This applies `-O` (optimized kernels), `-w N` (workload profile), and `--force` to skip hardware warnings. Workload options: 1=Low, 2=Default, 3=High (default), 4=Nightmare. Adjust based on system load (higher = faster but GPU becomes unresponsive for other tasks).

### Full Recovery with Custom Hashcat Options

```bash
python crack_runner.py seed.json target.hash -m 1000 \
    --work-dir ./rar_recovery \
    --prefix passwords \
    --hashcat-bin C:\hashcat\hashcat.exe \
    --hashcat-cwd C:\hashcat \
    --dictgen-args "--min-length 6 --max-length 12 --max-repeat 3" \
    --hashcat-args "--force -O -w 3" \
    --keep-dictionaries \
    --log-level DEBUG
```

### Windows PowerShell Helper

```powershell
.\run.ps1  # Executes: python crack_runner.py seed.json file.rar.hash -m 13000 ...
```

## Configuration

### Seed Dictionary Format

#### Plain Text (.txt)

One piece per line:

```
admin
root
2023
123
!@#
```

#### JSON (.json)

Full schema with rules:

```json
{
  "pieces": [
    { "value": "admin", "positions": "first" },
    { "value": "root", "exclude_positions": ["first", 2] },
    "2023",
    { "value": "123", "max_repeat": 2 },
    { "value": "qwerty", "repeatable": false },
    { "value": "!", "positions": "last" },
    { "value": "@", "positions": "last" },
    { "value": "#", "positions": ["first", 3] }
  ],
  "exclusive_groups": [
    ["!", "@", "#"]
  ],
  "requires": [
    { "if": "2023", "then": ["admin"] }
  ],
  "relations": [
    { "pieces": ["root", "123"], "mode": "together" },
    { "pieces": ["qwerty", "123"], "mode": "separate" },
    { "pieces": ["admin", "2023"], "mode": "order" }
  ]
}
```

**Piece Rules:**
- `"repeatable": false` — Piece may be used at most once per password
- `"max_repeat": N` — Piece may be used at most N times (overrides global `--max-repeat`)
- `"positions": [...]` — Allow-list of slots: integers (1-based), `"first"`, `"last"`, `"middle"`, `"any"`
- `"exclude_positions": [...]` — Deny-list of slots (same tokens as `positions`)

**Groups & Constraints:**
- `exclusive_groups` — Mutual exclusion: at most one piece per group in any password
- `requires` — Conditional requirements: "if piece A appears, piece B must also appear"
- `relations` — Multi-piece constraints:
  - `"together"` — Pieces must form a contiguous block
  - `"separate"` — Pieces cannot be adjacent
  - `"order"` — Pieces must appear in the specified sequence
  - `"any"` — Explicitly unrestricted (no-op)

### Command-Line Arguments

#### crack_runner.py

```
positional arguments:
  seed                  Seed dictionary (.txt or .json)
  target                Hash string or path to hash file
  -m, --hash-type       hashcat -m hash type (e.g., 13000 for RAR5)

optional arguments:
  --work-dir            Directory for dictionary files (default: hashcat_run_<timestamp>)
  --prefix              Output file prefix (default: 'dict')
  --dict-gen-script     Path to dict_gen.py (default: auto-detect)
  --python              Python executable for dict_gen (default: current interpreter)
  --hashcat-bin         hashcat executable path (default: 'hashcat')
  --hashcat-cwd         Working directory for hashcat (default: auto-detect for portable installs)
  --dictgen-args        Extra dict_gen arguments, quoted as one string
  --hashcat-args        Extra hashcat arguments, quoted as one string
  --performance         Apply standard speed-oriented hashcat flags: -O (optimized kernels),
                        -w (workload profile), and --force (skip hardware warnings)
  --workload            Workload profile for --performance: 1=Low, 2=Default, 3=High (default),
                        4=Nightmare (GPU unresponsive). Has no effect without --performance
  --poll-interval       Seconds between checks for new files (default: 1.0)
  --keep-dictionaries   Keep each file after hashcat tries it (default: delete)
  --force               Allow reusing work-dir with existing files
  --log-file            Path to run history log (default: <work-dir>/crack_runner.log)
  --log-level           Log verbosity: DEBUG, INFO, WARNING, ERROR (default: INFO)
  --log-max-bytes       Rotate log after size in bytes (default: 5MB)
  --log-backups         Number of rotated logs to keep (default: 3)
```

#### dict_gen.py

```
positional arguments:
  dictionary            Seed dictionary (.txt or .json)

optional arguments:
  --min-length          Minimum word length (default: 0)
  --max-length          Maximum word length (default: 32)
  --prefix              Output file prefix (default: 'dict')
  --out-dir             Output directory (default: current directory)
  --split-size          Split files by size, e.g., '10MB', '500K', '2GiB'
  --split-count         Split files by word count
  --max-repeat          Max repetitions of a piece per word
  --resume              Resume from a previous interrupted run: detect existing output files,
                        skip words already written, and continue generation in the next file.
                        Synchronizes with crack_runner.py for seamless recovery
  --quiet               Suppress progress display
```

## Output

### Dictionary Files

Generated as `<prefix>-1.txt`, `<prefix>-2.txt`, etc., with one candidate password per line.

### Logs

**crack_runner.log** contains a compact run history:

```
2025-08-24 12:34:56,789 INFO START config={'seed': Path('seed.json'), 'hash_type': 13000, ...}
2025-08-24 12:34:57,012 INFO GEN START pid=12345
2025-08-24 12:34:59,456 INFO FILE TAKEN dict-1.txt words=50000
2025-08-24 12:35:02,789 INFO FILE DONE dict-1.txt words=50000 rc=1 cracked=False  cumulative=50000/10000000 (0.5%)
2025-08-24 12:35:05,234 INFO CRACKED dict-1.txt:password123
```

## How It Works

### Dictionary Generation Pipeline

1. **Seed Loading**: Parse dictionary file (plain text or JSON with rules)
2. **Combination Generation**: DFS traversal of piece sequences, respecting all constraints
3. **Validation**: Each candidate is checked against position rules, requirements, and relations
4. **Output Splitting**: Words are streamed to files, rolling over when size or count limits are reached
5. **Progress Tracking**: Live bar shows words/sec, ETA, and file-by-file details

### Resume Process

When `--resume` is passed to dict_gen.py:

1. **File Discovery**: Scan output directory for existing `<prefix>-N.txt` files
2. **Word Count**: Count total words already written across all files
3. **Skip Calculation**: Advance file index and calculate skip count for generation
4. **Skipping**: During DFS generation, count candidates and skip writing the first N matches
5. **Continuation**: Resume writing from file N+1 onward, as if never interrupted

This allows both dict_gen.py (when called standalone or via `--dictgen-args "--resume"`) and crack_runner.py (which manages its own resume state) to work synchronously after an interruption.

### Cracking Orchestration

1. **Generator Start**: Launch dict_gen.py as a background subprocess, logging output
2. **Polling Loop**:
   - Discover newly finished dictionary files
   - Wait for generation to move to the next file (ensures safe reads)
   - Launch hashcat with current file
   - Check for cracked passwords via `hashcat --show`
3. **Early Exit**: Stop generator and terminate on success or exhaustion
4. **Resume Support**: On restart, crack_runner detects completed files, skips them, and passes `--resume` to dict_gen to continue seamlessly
5. **Logging**: Record every event for reproducibility and debugging

## Windows Compatibility

The project is designed for Windows and Unix systems:

- **Progress bars**: Automatically falls back from ANSI escape sequences to carriage-return updates on legacy cmd.exe
- **Portable hashcat**: Auto-detects and sets working directory for portable distributions
- **Path handling**: Resolves paths correctly across platforms
- **PowerShell integration**: `run.ps1` script for easy execution

## Testing

Test files are included:

- `test.rar` — Small RAR archive for validation
- `test.rar.hash` — Hash extracted from test.rar (RAR5 mode 13000)
- `seed_example.json` — Example seed configuration with all constraint types

Extract hash from a RAR file:

```bash
hashcat -m 13000 --example-hashes | head -1  # See format
hashcat -m 13000 file.rar  # hashcat extracts it automatically
```

## Recommendations

1. **Start Small**: Test with a simple seed file and narrow length range before scaling
2. **Estimate Output**: Use dict_gen to estimate total words before a long recovery attempt
3. **Monitor Disk**: Dictionary files can grow rapidly; use `--split-size` or `--split-count` to manage space
4. **Log Rotation**: Long-running recoveries benefit from log rotation (configured via `--log-max-bytes` and `--log-backups`)
5. **Resume Best Practices**:
   - If interrupted, always rerun with the **same `--work-dir` and `--prefix`** and the same `--dictgen-args`
   - Both scripts automatically detect existing files and resume without manual intervention
   - dict_gen.py will skip already-written words and continue in the next file
   - crack_runner.py will skip already-tried files and continue with the next one
   - No cleanup or `--force` flag needed—resume is designed to be safe and non-destructive
   - Different parameters (seed, `--min-length`, `--max-length`, etc.) on resume may produce inconsistent results
6. **Performance Mode**: Use `--performance` for GPU acceleration with sensible defaults:
   - **Default (`--workload 3`)**: Balances speed and system responsiveness; suitable for most scenarios
   - **High (`--workload 4`)**: Maximum speed but GPU becomes unresponsive; use only for dedicated recovery machines
   - **Low (`--workload 1`)**: Minimal system impact; use when running alongside other tasks
   - Note: Some hash types with `-O` flag cap password length; check hashcat docs if needed
7. **Custom Optimization**: For fine-tuned control, skip `--performance` and use `--hashcat-args` directly

## Troubleshooting

### "No such file or directory" (hashcat)

**Problem**: Portable hashcat fails to find OpenCL or modules.

**Solution**: Specify `--hashcat-cwd` explicitly:
```bash
python crack_runner.py ... --hashcat-cwd C:\hashcat
```

### Generator stops early

**Problem**: dict_gen.py exits before exhausting possibilities.

**Cause**: Often due to hitting default `--max-length` or running out of disk space.

**Solution**: Increase `--max-length` or use `--split-size` to keep files bounded.

### Hashcat not found

**Problem**: "hashcat executable not found"

**Solution**: Install hashcat or specify its full path:
```bash
python crack_runner.py ... --hashcat-bin /usr/bin/hashcat
```

### Windows VT mode

**Problem**: Progress bar shows garbled characters on Windows 10/11.

**Solution**: This shouldn't occur—dict_gen automatically enables VT mode. If it happens, `--quiet` suppresses the bar entirely.

## Performance Notes

- **Dictionary size grows combinatorially**: With 10 pieces and `--max-length 20`, expect millions of combinations
- **Generator is the bottleneck**: Disk I/O and rule checking are the limiting factors; hashcat typically runs faster
- **Streaming is efficient**: The file-by-file approach minimizes peak memory and disk usage
- **Position/relation rules**: Complex constraints can slow generation significantly; test with `--quiet` to measure
- **`--performance` mode**: Applies `-O`, `-w`, and `--force` to hashcat. User-supplied `--hashcat-args` take precedence if overlapping (e.g., `--hashcat-args "-w 2"` downgrades workload despite `--performance` default). Use `--performance` for GPU-accelerated recoveries; disable with custom `--hashcat-args` for CPU-only cracking

## License

See LICENSE file (if present) or contact the author for terms.

## Contributing

Pull requests and bug reports are welcome. Please include test cases for new features and rule constraints.
