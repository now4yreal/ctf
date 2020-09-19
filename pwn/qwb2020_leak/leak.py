#!/usr/bin/python
import sys
import uuid
from ctypes import CDLL, c_char_p
from threading import Timer
import os, random

import hashlib
import random
import string

def generatepow(difficulty):
    prefix = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
    msg="sha256("+prefix+"+?).binary.startswith('"+"0"*difficulty+"')"
    return prefix,msg

def checkpow(prefix,difficulty,answer):
    hashresult=hashlib.sha256(prefix+answer).digest()
    bits=''.join(bin(ord(i))[2:].zfill(8) for i in hashresult)
    assert bits.startswith('0'*difficulty)
    print "[+] passed"


def gen_binary():
    name = str(uuid.uuid1())
    code = '''
        #define _GNU_SOURCE
        #include <stdio.h>
        '''

    v = random.randrange(10000)
    for i in xrange(v):
        code += 'void not_my_flag{0}(){{printf("not a flag!\\n");}}\n'.format(i)

    with open('flag', 'r') as f:
        FLAG = f.read().strip()

    code += 'void yes_ur_flag(){{ char flag[]={{"{0}"}}; puts(flag);}}\n'.format(FLAG)

    for i in xrange(10000-v):
        code += 'void not_ur_flag{0}(){{printf("not a flag!\\n");}}\n'.format(i)

    with open('/tmp/lib%s.c' %name, 'w') as f:
        f.write(code)

    os.system('gcc -o /tmp/lib%s.so /tmp/lib%s.c -fPIC -shared -ldl 2> /dev/null' % (name, name))
    return '/tmp/lib%s.so' % name



class MyTimer():
    timer = None

    def __init__(self):
        self.timer = Timer(TIME, self.dispatch, args=[])
        self.timer.start()

    def dispatch(self):
        print 'time expired! bye!'
        sys.stdout.flush()
        os._exit(0)

if __name__ == '__main__':
    prefix, msg = generatepow(16)
    print '[+]', msg
    sys.stdout.flush()
    answer = raw_input("[-] ?=")
    checkpow(prefix, 16, answer)
    token = raw_input('[+] teamtoken:')
    if len(token.strip()) != 32:
        exit(0)

    libname = gen_binary()

    libc = CDLL('libc.so.6')
    flag = CDLL(libname)
    TIME = 10
    MyTimer()

    for i in xrange(5):
        sys.stdout.write('addr?:')
        sys.stdout.flush()
        addr = int(raw_input(), 16)
        libc.write(1, c_char_p(addr), 16)

