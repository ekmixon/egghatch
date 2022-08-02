# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

import sys

from egghatch.misc import str_as_db
from egghatch.shellcode import Shellcode

def main():
    if len(sys.argv) != 2:
        print "Usage: python %s <sc.bin>" % sys.argv[0]
        exit(1)

    print Shellcode(open(sys.argv[1], "rb").read()).to_json()

def parse(payload):
    return Shellcode(payload).to_dict()

def as_text(payload):
    ret, sc = [], Shellcode(payload).to_dict()

    ret.extend((start, "bbl_0x%04x:" % start) for start, end in sc["bbl"])
    ret.extend(
        (addr, "    0x%04x: %s %s" % (addr, mnemonic, operands))
        for addr, size, mnemonic, operands in sc["text"]
    )

    ret.extend((off, f".db {str_as_db(data)}") for off, data in sc["data"])
    # Sort each newline. Precedence is identified by the (offset, index) tuple
    # where index indicates the index in the ret list, i.e., bbl has a higher
    # priority than the instructions.
    ret = sorted((off, idx, line) for idx, (off, line) in enumerate(ret))
    return "%s\n" % "\n".join(line.rstrip() for off, idx, line in ret)
