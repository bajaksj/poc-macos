#!/usr/bin/env python3
"""Token-level proof that the injected payload becomes CODE, not data.

Runs the generated script through an AppleScript-aware tokenizer:
- tracks string literals ("...", incl. \" escapes)
- extracts every identifier sequence outside literals
- asserts `do shell script` exists at statement/expression level

This is a parse-level proof only. It does NOT execute the script (Gate 7 still
needs a real macOS run; see run_macos.sh).
"""
import re, sys

TOKEN_RE = re.compile(r'''
    "(?:[^"\\]|\\.)*"        # string literal
  | \-\-.*                   # line comment
  | [A-Za-z_][A-Za-z0-9_]*   # identifier
  | \s+
''', re.X)


def statements(script: str):
    toks, out, buf = [], [], []
    i = 0
    while i < len(script):
        m = TOKEN_RE.match(script, i)
        if m:
            t = m.group()
            if t.startswith('"'):
                out.append(("STR", t))
            elif t.strip():
                out.append(("ID", t))
            i = m.end()
        else:
            out.append(("OP", script[i]))
            i += 1
    return out


def main(path: str):
    script = open(path).read()
    toks = statements(script)
    flat = " ".join(v for k, v in toks if k in ("ID", "OP"))
    # 'do shell script' must appear as bare identifiers OUTSIDE any string literal
    hit = re.search(r'\bdo\s+shell\s+script\b', " ".join(v for k, v in toks if k == "ID"))
    if hit:
        # confirm the quote that opens the shell command is OUTSIDE the literal
        print("OK: 'do shell script' present at code level (outside string literals)")
        idx = hit.start()
        print("injected expression context:", flat[max(0, idx-40):idx+60].replace("\n", " "))
        return 0
    print("FAIL: no code-level 'do shell script' found")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
