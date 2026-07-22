#!/usr/bin/env python3
"""
redos_checker.py — Detect regex patterns that may be vulnerable to
Regular Expression Denial of Service (ReDoS), a.k.a. "evil regexes".

Two detection strategies are combined:

1. STATIC ANALYSIS
   Parses the regex into its AST (using Python's internal `re` parser)
   and looks for the classic evil-regex shapes:
     - Nested quantifiers:      (a+)+   (a*)*   (a+)*   ([a-z]*)+
     - Quantified alternation with overlapping branches:
                                 (a|a)+   (a|ab)+   (x+|x+)+

2. DYNAMIC TESTING
   Actually runs the regex against crafted "attack strings" of growing
   length (a run of matching chars followed by one character that
   breaks the match) with a hard timeout. If matching time blows up
   super-linearly as the input grows, that's a real, measured ReDoS —
   independent of whether the static analysis flagged anything.

Usage:
    python redos_checker.py                # interactive prompt
    python redos_checker.py "^(a+)+$"       # single pattern via CLI
    python redos_checker.py -f patterns.txt # one pattern per line
    python redos_checker.py --no-color ...  # disable ANSI colors
"""

import re
import os
import sys
import time
import shutil
import argparse
from multiprocessing import Process, Queue

# `re._parser` is the module name from Python 3.11+, it used to be `sre_parse`.
try:
    import re._parser as sre_parse
except ImportError:  # Python < 3.11
    import sre_parse  # type: ignore

MAX_REPEAT = sre_parse.MAXREPEAT if hasattr(sre_parse, "MAXREPEAT") else None


# ---------------------------------------------------------------------------
# TERMINAL COLORS / STYLE
# ---------------------------------------------------------------------------

class C:
    """ANSI color codes. Disabled globally via C.disable() for --no-color
    or non-tty output."""
    ENABLED = True

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"

    RED = "\033[38;5;203m"
    GREEN = "\033[38;5;114m"
    YELLOW = "\033[38;5;221m"
    ORANGE = "\033[38;5;208m"
    BLUE = "\033[38;5;75m"
    CYAN = "\033[38;5;80m"
    MAGENTA = "\033[38;5;170m"
    GREY = "\033[38;5;244m"
    WHITE = "\033[38;5;255m"

    BG_RED = "\033[48;5;52m"
    BG_GREEN = "\033[48;5;22m"
    BG_YELLOW = "\033[48;5;58m"

    @classmethod
    def disable(cls):
        cls.ENABLED = False
        for attr in list(vars(cls).keys()):
            if attr.isupper():
                setattr(cls, attr, "")

    @classmethod
    def wrap(cls, text, *codes):
        if not cls.ENABLED:
            return text
        return "".join(codes) + str(text) + cls.RESET


def _supports_color():
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        return True
    return os.environ.get("TERM", "") != "dumb"


TERM_WIDTH = shutil.get_terminal_size(fallback=(78, 20)).columns
BOX_WIDTH = max(60, min(TERM_WIDTH, 96))


# ---------------------------------------------------------------------------
# BANNER
# ---------------------------------------------------------------------------

BANNER = r"""                                             ___
                                          ,o88888
                                       ,o8888888'
                 ,:o:o:oooo.        ,8O88Pd8888"
             ,.::.::o:ooooOoOoO. ,oO8O8Pd888'"
           ,.:.::o:ooOoOoOO8O8OOo.8OOPd8O8O"
          , ..:.::o:ooOoOOOO8OOOOo.FdO8O8"
         , ..:.::o:ooOoOO8O888O8O,COCOO"
        , . ..:.::o:ooOoOOOO8OOOOCOCO"                   
         . ..:.::o:ooOoOoOO8O8OCCCC"o
            . ..:.::o:ooooOoCoCCC"o:o                
            . ..:.::o:o:,cooooCo"oo:o:
         `   . . ..:.:cocoooo"'o:o:::'
         .`   . ..::ccccoc"'o:o:o:::'
        :.:.    ,c:cccc"':.:.:.:.:.'
      ..:.:"'`::::c:"'..:.:.:.:.:.'
    ...:.'.:.::::"'    . . . . .'
   .. . ....:."' `   .  . . ''
 . . . ...."'
 .. . ."'     
. 

 ███████████   ██████████ ██████████      ███████     █████████ 
░░███░░░░░███ ░░███░░░░░█░░███░░░░███   ███░░░░░███  ███░░░░░███
 ░███    ░███  ░███  █ ░  ░███   ░░███ ███     ░░███░███    ░░░ 
 ░██████████   ░██████    ░███    ░███░███      ░███░░█████████ 
 ░███░░░░░███  ░███░░█    ░███    ░███░███      ░███ ░░░░░░░░███
 ░███    ░███  ░███ ░   █ ░███    ███ ░░███     ███  ███    ░███
 █████   █████ ██████████ ██████████   ░░░███████░  ░░█████████ 
░░░░░   ░░░░░ ░░░░░░░░░░ ░░░░░░░░░░      ░░░░░░░     ░░░░░░░░░  
"""


def print_banner():
    if not C.ENABLED:
        print("=== REDOS CHECKER ===")
        print("created by Amirreza Rashidi !")
        print("-" * BOX_WIDTH)
        return

    lines = BANNER.strip("\n").split("\n")
    gradient = [C.RED, C.ORANGE, C.YELLOW, C.GREEN, C.CYAN]
    for i, line in enumerate(lines):
        color = gradient[i % len(gradient)]
        print(C.wrap(line, C.BOLD, color))
    subtitle = "evil regex detector — static AST analysis + timed attack strings"
    print(C.wrap(subtitle.center(BOX_WIDTH), C.ITALIC, C.GREY))
    print(C.wrap("=" * BOX_WIDTH, C.GREY))


# ---------------------------------------------------------------------------
# STATIC ANALYSIS
# ---------------------------------------------------------------------------

REPEAT_OPS = {"MAX_REPEAT", "MIN_REPEAT"}


def _opname(op):
    """Normalize opcode to a plain string across Python versions."""
    return str(op).split(".")[-1]


def _first_chars(subpattern, depth=0):
    """
    Best-effort approximation of the set of characters a subpattern could
    start matching with. Used to check whether two alternation branches
    can overlap. Returns None if we can't determine it (treated as "may
    overlap", i.e. conservative/pessimistic).
    """
    if depth > 20:
        return None
    try:
        items = list(subpattern)
    except TypeError:
        return None
    if not items:
        return {""}  # matches empty string

    op, av = items[0]
    name = _opname(op)

    if name == "LITERAL":
        return {chr(av)}
    if name == "NOT_LITERAL":
        return None  # "anything but X" — treat as unknown/overlapping
    if name == "IN":
        chars = set()
        for sub_op, sub_av in av:
            sub_name = _opname(sub_op)
            if sub_name == "LITERAL":
                chars.add(chr(sub_av))
            elif sub_name == "RANGE":
                lo, hi = sub_av
                if hi - lo > 64:  # avoid huge expansions, just sample
                    return None
                chars.update(chr(c) for c in range(lo, hi + 1))
            else:
                return None
        return chars
    if name == "SUBPATTERN":
        inner = av[-1]
        return _first_chars(inner, depth + 1)
    if name == "BRANCH":
        _, branches = av
        result = set()
        for b in branches:
            fc = _first_chars(b, depth + 1)
            if fc is None:
                return None
            result |= fc
        return result
    if name in REPEAT_OPS:
        mn, mx, inner = av
        fc = _first_chars(inner, depth + 1)
        if mn == 0:
            return fc  # could also match empty then move on — approximate
        return fc
    if name == "AT":
        return {""}  # anchors don't consume characters
    # ANY, CATEGORY, etc. — unknown, treat conservatively
    return None


def _branches_overlap(branches):
    seen = set()
    for b in branches:
        fc = _first_chars(b)
        if fc is None:
            return True  # can't prove disjoint -> assume overlap (conservative)
        if fc & seen:
            return True
        seen |= fc
    return False


def _walk(subpattern, inside_quantifier, findings, path="root"):
    try:
        items = list(subpattern)
    except TypeError:
        return

    for op, av in items:
        name = _opname(op)

        if name in REPEAT_OPS:
            mn, mx, inner = av
            unbounded = (mx is None) or (MAX_REPEAT is not None and mx == MAX_REPEAT) or mx > 5
            if inside_quantifier and unbounded:
                findings.append((
                    "NESTED_QUANTIFIER",
                    "HIGH",
                    f"A repeated group contains another unbounded repetition "
                    f"at '{path}'. Classic exponential-blowup shape like (a+)+."
                ))
            # recurse, now marking we're inside a quantifier
            _walk(inner, inside_quantifier or unbounded, findings, path + " > repeat")

        elif name == "BRANCH":
            _, branches = av
            if inside_quantifier and _branches_overlap(branches):
                findings.append((
                    "AMBIGUOUS_ALTERNATION",
                    "HIGH",
                    f"Alternation branches at '{path}' overlap and sit inside a "
                    f"repetition. Classic shape like (a|a)+ or (a|ab)+."
                ))
            for b in branches:
                _walk(b, inside_quantifier, findings, path + " > branch")

        elif name == "SUBPATTERN":
            inner = av[-1]
            _walk(inner, inside_quantifier, findings, path + " > group")

        elif name in ("MAX_REPEAT".lower(),):
            pass
        else:
            # ASSERT / ASSERT_NOT / other wrappers hold a sub-subpattern
            if isinstance(av, tuple) and len(av) >= 1 and hasattr(av[-1], "__iter__"):
                try:
                    _walk(av[-1], inside_quantifier, findings, path + f" > {name.lower()}")
                except TypeError:
                    pass


def static_analyze(pattern):
    findings = []
    try:
        parsed = sre_parse.parse(pattern)
    except re.error as e:
        return None, [("INVALID_REGEX", "N/A", f"Pattern does not compile: {e}")]
    _walk(parsed, False, findings)
    return parsed, findings


# ---------------------------------------------------------------------------
# DYNAMIC TESTING (actually attack the regex under a timeout)
# ---------------------------------------------------------------------------

def _match_worker(pattern, text, queue):
    try:
        compiled = re.compile(pattern)
        start = time.perf_counter()
        compiled.search(text)
        queue.put(time.perf_counter() - start)
    except Exception as e:
        queue.put(f"ERROR: {e}")


def _timed_match(pattern, text, timeout):
    """Run the match in a separate process so a runaway regex can be killed."""
    q = Queue()
    p = Process(target=_match_worker, args=(pattern, text, q))
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        p.join()
        return None  # None => timed out
    if not q.empty():
        result = q.get()
        if isinstance(result, str):
            return result  # error message
        return result
    return None


def dynamic_test(pattern, timeout=1.0, lengths=(5, 10, 15, 20, 25, 30, 35), on_step=None):
    """
    Attacks the pattern with growing "poison" strings: a run of a
    plausible matching character followed by one character guaranteed
    to make the overall match fail (forcing the engine to backtrack
    through every possibility before giving up).

    `on_step(n, elapsed_or_None)` is called after each attempt, so the
    caller can render live progress.
    """
    results = []
    timed_out_at = None

    for n in lengths:
        text = "a" * n + "!"  # breaks the match, forces full backtracking
        elapsed = _timed_match(pattern, text, timeout)
        if elapsed is None:
            timed_out_at = n
            results.append((n, None))
            if on_step:
                on_step(n, None)
            break
        if isinstance(elapsed, str):
            return {"error": elapsed}
        results.append((n, elapsed))
        if on_step:
            on_step(n, elapsed)

    growth_flag = False
    times = [t for _, t in results if isinstance(t, float)]
    if len(times) >= 3:
        # crude super-linearity check: does time more than double each step
        # while input length only grows by a constant amount?
        ratios = [times[i + 1] / times[i] for i in range(len(times) - 1) if times[i] > 0]
        if ratios and max(ratios) > 3:
            growth_flag = True

    return {
        "timed_out_at": timed_out_at,
        "timings": results,
        "explosive_growth": growth_flag,
    }


# ---------------------------------------------------------------------------
# REPORTING / UI
# ---------------------------------------------------------------------------

RISK_COLOR = {
    "SAFE": C.GREEN,
    "MEDIUM": C.YELLOW,
    "HIGH": C.RED,
    "UNKNOWN": C.GREY,
    "N/A": C.GREY,
}

VERDICT_STYLE = {
    "VULNERABLE": (C.RED, C.BG_RED, "✖", "VULNERABLE"),
    "SUSPICIOUS": (C.YELLOW, C.BG_YELLOW, "⚠", "SUSPICIOUS"),
    "LIKELY SAFE": (C.GREEN, C.BG_GREEN, "✔", "LIKELY SAFE"),
}


def _badge(risk):
    color = RISK_COLOR.get(risk, C.GREY)
    return C.wrap(f" {risk} ", C.BOLD, color, C.UNDERLINE) if not C.ENABLED else \
        C.wrap(f" {risk} ", C.BOLD, color)


def _hline(char="─"):
    print(C.wrap(char * BOX_WIDTH, C.GREY))


def _bar(elapsed, scale_ms=200):
    """Render a small colored bar proportional to elapsed time (capped)."""
    if elapsed is None:
        return C.wrap("█" * 24 + " TIMEOUT", C.BOLD, C.RED)
    ms = elapsed * 1000
    filled = min(24, int((ms / scale_ms) * 24))
    filled = max(1, filled) if ms > 0 else 0
    color = C.GREEN if ms < scale_ms * 0.25 else (C.YELLOW if ms < scale_ms * 0.75 else C.RED)
    bar = C.wrap("█" * filled, color) + C.wrap("░" * (24 - filled), C.GREY)
    return f"{bar}  {ms:8.3f} ms"


def check_pattern(pattern, timeout=1.0, verbose=True):
    print()
    _hline("━")
    print(f" {C.wrap('PATTERN', C.BOLD, C.CYAN)}  {C.wrap(pattern, C.BOLD, C.WHITE)}")
    _hline("━")

    parsed, findings = static_analyze(pattern)
    if parsed is None:
        for _, _, msg in findings:
            print(f"  {C.wrap('✖ INVALID', C.BOLD, C.RED)}  {msg}")
        _hline()
        return {"pattern": pattern, "valid": False}

    static_risk = "SAFE"
    print(f"\n {C.wrap('▸ Static analysis', C.BOLD, C.BLUE)}")
    if findings:
        static_risk = "HIGH"
        print(f"   {_badge('HIGH')}  evil-regex structure detected")
        for kind, severity, msg in findings:
            print(f"   {C.wrap('•', C.RED)} {C.wrap(kind, C.BOLD)}: {msg}")
    else:
        print(f"   {_badge('SAFE')}  no nested-quantifier / ambiguous-alternation shape found")

    print(f"\n {C.wrap('▸ Dynamic attack test', C.BOLD, C.BLUE)}  "
          f"{C.wrap(f'(timeout {timeout}s per attempt)', C.DIM, C.GREY)}")

    def on_step(n, elapsed):
        if verbose:
            print(f"   len={n:>3}  {_bar(elapsed)}")

    dyn = dynamic_test(pattern, timeout=timeout, on_step=on_step)

    if "error" in dyn:
        print(f"   {_badge('UNKNOWN')}  could not run — {dyn['error']}")
        dynamic_risk = "UNKNOWN"
    else:
        if dyn["timed_out_at"] is not None:
            dynamic_risk = "HIGH"
            print(f"\n   {_badge('HIGH')}  TIMED OUT at input length "
                  f"{dyn['timed_out_at']} (>{timeout}s) — matching time exploded")
        elif dyn["explosive_growth"]:
            dynamic_risk = "MEDIUM"
            print(f"\n   {_badge('MEDIUM')}  matching time grows much faster than "
                  f"input length (possible poly/exponential blowup)")
        else:
            dynamic_risk = "SAFE"
            print(f"\n   {_badge('SAFE')}  matching time stayed roughly linear/flat")

    overall = "VULNERABLE" if "HIGH" in (static_risk, dynamic_risk) else (
        "SUSPICIOUS" if dynamic_risk == "MEDIUM" else "LIKELY SAFE"
    )
    color, bg, icon, label = VERDICT_STYLE[overall]
    print()
    _hline()
    verdict_line = f"  {icon}  VERDICT: {label}  "
    print(C.wrap(verdict_line, C.BOLD, C.WHITE, bg) if C.ENABLED else verdict_line)
    _hline("━")

    return {
        "pattern": pattern,
        "valid": True,
        "static_findings": findings,
        "dynamic": dyn,
        "verdict": overall,
    }


def print_summary(results):
    """Print a compact colored table after batch runs."""
    results = [r for r in results if r]
    if len(results) < 2:
        return
    print()
    print(C.wrap(" SUMMARY ".center(BOX_WIDTH, "="), C.BOLD, C.CYAN))
    for r in results:
        if not r.get("valid", False):
            status = C.wrap("INVALID", C.BOLD, C.GREY)
        else:
            color, _, icon, label = VERDICT_STYLE[r["verdict"]]
            status = C.wrap(f"{icon} {label}", C.BOLD, color)
        pat = r["pattern"]
        if len(pat) > BOX_WIDTH - 20:
            pat = pat[:BOX_WIDTH - 23] + "..."
        print(f"  {status:<30}  {C.wrap(pat, C.DIM)}")
    print(C.wrap("=" * BOX_WIDTH, C.CYAN))


def main():
    parser = argparse.ArgumentParser(description="Detect ReDoS-vulnerable ('evil') regex patterns.")
    parser.add_argument("pattern", nargs="?", help="A regex pattern to check")
    parser.add_argument("-f", "--file", help="File with one regex pattern per line")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                         help="Per-attempt timeout in seconds (default: 1.0)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("-q", "--quiet", action="store_true",
                         help="Hide per-length timing bars, show only verdicts")
    args = parser.parse_args()

    if args.no_color or not _supports_color():
        C.disable()

    print_banner()

    verbose = not args.quiet
    results = []

    if args.file:
        with open(args.file) as fh:
            patterns = [line.strip() for line in fh if line.strip()]
        for p in patterns:
            results.append(check_pattern(p, timeout=args.timeout, verbose=verbose))
        print_summary(results)
    elif args.pattern:
        check_pattern(args.pattern, timeout=args.timeout, verbose=verbose)
    else:
        print(f"\n{C.wrap('Enter a regex pattern to check', C.BOLD)} "
              f"{C.wrap('(empty line to quit)', C.DIM, C.GREY)}:")
        while True:
            try:
                prompt = C.wrap("regex> ", C.BOLD, C.CYAN)
                p = input(prompt).strip()
            except EOFError:
                break
            if not p:
                break
            results.append(check_pattern(p, timeout=args.timeout, verbose=verbose))
        print_summary(results)


if __name__ == "__main__":
    main()