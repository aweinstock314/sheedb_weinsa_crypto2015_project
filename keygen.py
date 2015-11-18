#!/usr/bin/env python
import os

KEY_LENGTH_BYTES = 128 / 8 # 128 bit keys

mkdir_ = lambda p: () if os.path.exists(p) else os.mkdir(p)

def main():
    for p in ['cards', 'includecards']:
        mkdir_(p)

    for name in ['Alice', 'Bob', 'Eve']:
        cryptkey = os.urandom(KEY_LENGTH_BYTES)
        signkey = os.urandom(KEY_LENGTH_BYTES)
        pin = ''.join([chr(ord('0') + ord(x) % 10) for x in os.urandom(4)])
        with open('cards/%s.card' % name, 'w') as f:
            f.write(pin + cryptkey + signkey)
        with open('includecards/%s.card.h' % name, 'w') as f:
            upcasename = name.upper()
            repr_cryptkey = repr(cryptkey)
            repr_signkey = repr(signkey)
            repr_pin = repr(pin)
            f.write(
'''
#ifndef {upcasename}_H
#define {upcasename}_H

const char* {name}_cryptkey = {repr_cryptkey};
const char* {name}_signkey = {repr_signkey};
const char* {name}_pin = {repr_pin};

#endif
'''.format(**locals()))
        print(name)
        print(pin)
        print(repr(cryptkey))
        print(repr(signkey))
        print('-'*5)

if __name__ == '__main__':
    main()
