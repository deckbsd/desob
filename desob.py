#!/usr/bin/python

import sys
import pefile

all = {}


def ROR(x, n, bits=32):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))


def ROL(x, n, bits=32):
    return ROR(x, bits - n, bits)

try:
    pe = pefile.PE(sys.argv[1])
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        b = 0
        for i in list(exp.name):
            c = ROL(b, 7)
            d = i ^ c
            b = d
        all[hex(d)] = exp.name
    if sys.argv[2].lower() in all:
        print(all[sys.argv[2].lower()])

    recover = sys.argv[2].lower()

except OSError as os:
    print(os)

except IndexError as e:
    print(e)

