程序第一次输入的是idea和sm4的密钥，第二次输入的是flag  

程序步骤:  

1.对两密钥进行rc4加密发送。rc4密钥已知，数据包已知，进而密钥可解  

2.对flag 4bytes一组作可逆变换  

3.对变换结果sm4加密  

4.对sm4加密经过idea加密，发送数据包  

结题过程是加密的逆过程。

PS:  

1.题目好像很吃机器？单一组值就out of memory  

2.python crypto库referance:https://www.dlitz.net/software/pycrypto/api/current/  

3.玩crypto常用的几个函数：  

hexlify:b'601020'->b'\x60\x10\x20'  

unhexlify:hexlify的反过程  

long_to_bytes:0x11223344->b'\x11\x22\x33\x44'  

bytes_to_long:long_to_bytes的反过程  

bytearray:将字符串、数组等转换为bytearray，因为一些一些加密库要求bytearray，直接传入str会报错  

4.要会mutiprocessing.pool多进程跑，附一个demo:  

```python3
#!/bin/python3
from z3 import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
from multiprocessing import Pool
from binascii import unhexlify,hexlify

import time
def run(arg):
    print(arg)
    time.sleep(100)
if __name__ == '__main__':
    with Pool(12) as p:
        p.map(run, [(i) for i in range(12)])

```