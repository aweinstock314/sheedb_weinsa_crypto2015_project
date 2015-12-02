#!/usr/bin/env python
import os

KEY_LENGTH_BYTES = 128 / 8 # 128 bit keys

mkdir_ = lambda p: () if os.path.exists(p) else os.mkdir(p)
quotify = lambda x: ''.join(['"', repr(x)[1:-1], '"'])
braceify = lambda x: ''.join(['{', repr(map(ord,x))[1:-1], '}'])

def main():
    for p in ['cards', 'includecards']:
        mkdir_(p)

    names = ['Alice', 'Bob', 'Eve']
    for name in names:
        cryptkey = os.urandom(KEY_LENGTH_BYTES)
        signkey = os.urandom(KEY_LENGTH_BYTES)
        pin = ''.join([chr(ord('0') + ord(x) % 10) for x in os.urandom(4)])
        with open('cards/%s.card' % name, 'w') as f:
            f.write(pin + cryptkey + signkey)
        with open('includecards/%s.card.h' % name, 'w') as f:
            upcasename = name.upper()
            repr_cryptkey = braceify(cryptkey)
            repr_signkey = braceify(signkey)
            repr_pin = quotify(pin)
            f.write(
'''
#ifndef CARD_{upcasename}_H
#define CARD_{upcasename}_H

const unsigned char {name}_cryptkey[] = {repr_cryptkey};
const unsigned char {name}_signkey[] = {repr_signkey};
const char* {name}_pin = {repr_pin};

#endif
'''.format(**locals()))
        print(name)
        print(pin)
        print(repr(cryptkey))
        print(repr(signkey))
        print('-'*5)
    with open('includecards/metacard.h', 'w') as f:
        f.write('''
#ifndef METACARD_H
#define METACARD_H
''')
        for name in names:
            f.write('#include "%s.card.h"\n' % name)
        f.write('#endif\n')

if __name__ == '__main__':
    main()
