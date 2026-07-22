# ReDoS Checker

A command-line tool that scans regex patterns for **ReDoS** vulnerabilities combining static structural analysis with a live, timed attack test  and reports the result in a colorful terminal UI.

![2](pics\2.png)

## What is ReDoS?

**ReDoS** (Regular Expression Denial of Service) is a vulnerability where a regex, run against a carefully (or accidentally) chosen input string, takes an amount of time that grows **exponentially** or **polynomially** with the input length instead of linearly.

 A string just a few dozen characters longer can push matching time from microseconds to minutes or hours 
enough to hang a single request thread, or an entire server if the regex runs on every incoming request (form validation, log parsing, header checks, etc.).

It happens because of how most regex engines (including Python's `re`, which is backtracking-based) handle **ambiguity**: when a part of the pattern could match the same input in more than one way, the engine tries every possible way before giving up. Two shapes cause this almost every
time:

- **Nested quantifiers** — `(a+)+`, `(a*)*`, `([a-z]+)*`
  The inner `+`/`*` can split a run of `a`s into groups in exponentially
  many ways, and the outer `+`/`*` tries all of them.
- **Overlapping alternation inside a quantifier** — `(a|a)+`, `(a|ab)+`,
  `(x+|x+)+`
  Each repetition can match the same characters via more than one
  branch, again multiplying the number of paths the engine explores.

A classic attack string is a long run of matching characters followed by one character that breaks the match (e.g. `"aaaaaaaaaaaaaaaaaaaa!"` against`^(a+)+$`) — the engine can't succeed no matter how it splits things up, so
it's forced to actually try every split before failing.

## What this tool does

`redos_checker.py` checks a regex two independent ways and combines the results into one verdict:

### 1. Static analysis (AST-based)

The pattern is parsed with Python's internal regex parser (`re._parser` /`sre_parse`) into its abstract syntax tree, then walked recursively to spot the two dangerous shapes above:

- **`NESTED_QUANTIFIER`** — an unbounded repeat (`+`, `*`, or a large
  `{m,n}`) found inside another repeat.
- **`AMBIGUOUS_ALTERNATION`** — an alternation (`a|b`) inside a repeat
  where the branches can match overlapping characters (approximated via a
  best-effort "what characters can this branch start with" analysis).

This catches known-bad *structure* even on patterns too slow to safely test, and doesn't require actually running the regex.

### 2. Dynamic testing (real attack, real timing)

The pattern is compiled and run against attack strings of increasing length (5, 10, 15, ... characters), each in its **own subprocess** with a hard timeout (default 1 second), so a truly catastrophic regex can be killed instead of hanging the tool. For each length it records how long matching took, and flags:

- **Timeout** — matching didn't even finish within the limit → `HIGH` risk.
- **Explosive growth** — timing more than triples between consecutive
  lengths even without timing out → `MEDIUM` risk (early warning of
  polynomial/exponential blowup before it gets catastrophic).
- Otherwise → `SAFE`, timing stayed roughly linear/flat.

This step catches real-world vulnerable patterns that the static heuristics might miss (or flags as safe things the static check couldn't prove safe).

### Combining the results

| Static | Dynamic | Verdict |
|---|---|---|
| `HIGH` or dynamic `HIGH` | — | **VULNERABLE** |
| otherwise | `MEDIUM` | **SUSPICIOUS** |
| `SAFE` | `SAFE` | **LIKELY SAFE** |

("Likely" safe, not "safe" — this is heuristic detection, not a formal proof; see Limitations below.)

![2](pics\3.png)

## Usage

```bash
# Interactive prompt
python redos_checker.py

# Check a single pattern
python redos_checker.py "^(a+)+$"

# Check every pattern in a file (one per line)
python redos_checker.py -f patterns.txt

# Adjust the per-attempt timeout (seconds)
python redos_checker.py -t 2.0 "^(a+)+$"

# Only show verdicts, hide the per-length timing bars
python redos_checker.py -q -f patterns.txt

# Disable colored output (e.g. for logging/CI)
python redos_checker.py --no-color -f patterns.txt
```

## Requirements

- Python 3.7+ (uses `re._parser` on 3.11+, falls back to `sre_parse` on older versions)
- No third-party dependencies — everything is standard library (`re`, `multiprocessing`, `argparse`, `shutil`)

## Limitations

- Static analysis is a **heuristic**, not a formal proof. It can miss more exotic vulnerable shapes and can flag structurally-suspicious patterns that turn out to be fine in practice.
- Dynamic testing only tries attack strings built from the character`a`. Patterns whose worst case depends on other characters or on multi-character alternatives may need custom attack strings to expose the blowup.
- Dynamic testing is bounded by the `lengths` tested (5–35 by default) and the timeout — a regex that's merely slow-but-polynomial might not blow up within that window and could be under-reported.
- This tool is for **your own patterns** during development/review — don't point it at untrusted regexes from strangers without sandboxing beyond what's already here (the subprocess+timeout guard helps, but isn't a
  full sandbox).
