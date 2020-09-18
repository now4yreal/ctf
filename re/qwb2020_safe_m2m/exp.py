#!/bin/python3
from z3 import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import ARC4
from multiprocessing import Pool
from binascii import unhexlify,hexlify
from pysm4 import encrypt,decrypt
from pyidea import IdeaAlgorithm
import time

start_time=time.time()
rc4_key=unhexlify('1f ef aa fe 12 4f f4 5f 1a 90'.replace(' ',''))
enced_key=unhexlify('60 dc bc f3 57 8f d2 16 fd b9 1e d8 aa c9 34 d6 50 dc 16 87 57 8f f7 2f 7f a7 8d 21 aa d9 66 e5'.replace(' ',''))
enced_text=unhexlify('a2 77 1a 22 48 84 73 e7 32 fd bc 96 5f 64 60 46 d3 f5 9f b3 84 d4 8f 24 a3 c6 aa cb e1 94 7d 58 1c a3 e4 12 e7 b7 86 86 7d 9b 0c ad ee b3 ee 11'.replace(' ',''))

rc4=ARC4.new(rc4_key)
idea_key=rc4.decrypt(enced_key[:16])
rc4=ARC4.new(rc4_key)
sm4_key=rc4.decrypt(enced_key[16:])
print("idea_key:"+str(hexlify(idea_key)))
print("sm4_key:"+str(hexlify(sm4_key)))

idea=IdeaAlgorithm(bytes_to_long(idea_key))
deced_text2=b''
for i in range(0,48,8):
    deced_text2+=long_to_bytes(idea.decrypt(bytes_to_long(enced_text[i:i+8])))
print("idea_decryed_text:"+str(hexlify(deced_text2)))


deced_text1=b''
for i in range(0,48,16):
    deced_text1+=long_to_bytes(decrypt(bytes_to_long(deced_text2[i:i+16]),bytes_to_long(sm4_key)))
print("sm4_decryed_text:"+str(hexlify(deced_text1)))


from z3 import *
flag=[BitVec('z'+str(i),32) for i in range(12)]
s=Solver()
for i in range(12):
    for j in range(100016):
        flag[i]^=LShR((flag[i] ^ (32 * flag[i])) , 17) ^ 32 * flag[i] ^ ((LShR((flag[i] ^ (32 * flag[i])), 17) ^ flag[i] ^ 32 * flag[i]) << 13)

for i in range(1):
    s.add(flag[i]==bytes_to_long(deced_text1[4*i:4*i+4][::-1]))
print (s.check())
end_time=time.time()
print("running time:"+hex(end_time-start_time))
result=''
for i in range(1):
    result+=long_to_bytes(s.model()['z'+str(i)].as_long())
print(result)


