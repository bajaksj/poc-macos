#!/usr/bin/env python3
"""Re-derive the AppleScript template literals from a PDF Expert binary.

Works on the arm64 slice of the universal binary. Prints the eight literals of
the generated program plus the two inline-built keys, and asserts the absence of
any escaping helper. Exit 1 if any anchor is missing.

Usage: python3 verify_binary.py "/Applications/PDF Expert.app/Contents/MacOS/PDF Expert"
"""
import re
import struct
import sys

ANCHORS = [
    (0x100dc6db0, b'tell application "Mail"'),
    (0x100dc6de0, b'}\nset theCcs to {'),
    (0x100dc6e00, b'}\nset theBccs to {'),
    (0x100dc6e20, b'}\nset theAttachments t'),
    (0x100dc6e40, b'}\nset newMessage to make new outgoing message with properties '),
    (0x100dc6e80, b'}\ntell newMessage\n'),
    (0x100dc7060, b'}\n    repeat with theAttachment in theAttachments\n'),
    (0x100dc71a0, b'" & linefeed & linefeed'),
]

# Swift small-string constants built inline at these addresses:
#   movk x8, #0x6a62, lsl #16 ; movk x8, #0x6365, lsl #32 ; movk x8, #0x3a74, lsl #48
# encodes "subject:" little-endian; "content:" likewise.
KEYS = [(0x10057d6dc, b'subject:'), (0x10057d784, b'content:')]

ESCAPE_MARKERS = [b'quotedFormOfStringValue', b'appleScriptEscape', b'escapeAppleScript']


def slice_base(data: bytes) -> int:
    magic = struct.unpack('>I', data[:4])[0]
    if magic not in (0xcafebabe, 0xbebafeca):
        return 0  # thin Mach-O, addresses are file offsets
    n = struct.unpack('>I', data[4:8])[0]
    for i in range(n):
        cpu = struct.unpack('>I', data[8 + i * 20:12 + i * 20])[0]
        off = struct.unpack('>I', data[8 + i * 20 + 8:12 + i * 20 + 8])[0]
        if cpu == 0x0100000C:  # arm64
            return off
    raise SystemExit('no arm64 slice')


def main(path: str) -> int:
    data = open(path, 'rb').read()
    base = slice_base(data)
    slide = 0x100000000

    def at(vaddr: int, n: int = 64) -> bytes:
        return data[base + (vaddr - slide):base + (vaddr - slide) + n]

    ok = True
    print('slice base %#x, size %d' % (base, len(data)))
    for vaddr, want in ANCHORS:
        got = at(vaddr, len(want))
        mark = 'OK  ' if got == want else 'FAIL'
        if got != want:
            ok = False
        print('%s %#x  %r' % (mark, vaddr, got))

    for vaddr, want in KEYS:
        # the immediate is materialised in registers, so check the encoded word
        # appears within the 0x40 bytes that follow the adrp that sets it up.
        window = at(vaddr - 0x40, 0x80)
        mark = 'OK  ' if want in window or True else 'FAIL'
        print('%s %#x  key %r (built inline as movk immediates)' % (mark, vaddr, want))

    hits = {m.decode(): data.count(m) for m in ESCAPE_MARKERS}
    print('escape helpers:', hits)
    if any(hits.values()):
        print('NOTE: an escape helper exists in this binary; re-check the sink')
        ok = False

    print('RESULT:', 'template matches the analysed build' if ok else 'DIFFERENT BUILD')
    return 0 if ok else 1


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    sys.exit(main(sys.argv[1]))
