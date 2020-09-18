#!/usr/bin/env python3

import string
import subprocess
import hashlib

brain_num = 6

def md5(x):
    m = hashlib.md5()
    m.update(x)
    return m.hexdigest()

def check_brain(brain, thought):
    p = subprocess.run(["./bf", brain], input=(thought+'\n').encode(), stdout=subprocess.PIPE)
    r = p.stdout.strip()
    return r == b"good"

if __name__ == "__main__":
    print("Do you know what a baby is thinking in his brain?")
    print("If there are multiple answers, give me the shortest one.")
    thought = input("> ").strip()
    assert all(x in string.digits for x in thought)
    for i in range(brain_num):
        print("check",i)
        if not check_brain("brain%d"%i, thought):
            print("wrong")
            exit()
    print("flag{%s}" % md5(thought.encode()))
