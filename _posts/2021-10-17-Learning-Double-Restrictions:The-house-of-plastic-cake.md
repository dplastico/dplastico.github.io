---
layout: post
title: Learning double Free Restrictions, the (not really a house) house of plastic-cake
date: 2021-10-17
comments: true
categories: [Sin categoría]
---
# The house of plastic cake
 
In the last couple of weeks I've been working on some streams and studying around [tcache poisoning](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/tcache_poisoning.c) and I decided to learn more about the tcache double free (I will refer also as DF) [mitigations](https://blog.infosectcbr.com.au/2019/09/linux-heap-glibc-tcache-double-free.html) and ways to leverage overlaped chunks using just this bug. I saw that almost all the tecniques uses leaks, so using some knwoledge I came with a workaround for the [house of botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/house_of_botcake.c) to drop a shell on binaries with just DF bugs, that doesn't leak any addresses and have no read or edit functions.
 
This is really not a "house" and I'm not claming it to be a new explotation tecnique, but its a good workaround and learning exercise that actually merge 2 tecniques together to achieve the final result. It was tested in glibc 2.27, 2.29 and 2.31. I didnt test it far that and some new mitigations could make this tecnique invalid or maybe some variations are required

# Background knowledge

If the reader is not familiar with the topics discussed in this post this may help:

- [Double Free](https://heap-exploitation.dhavalkapil.com/attacks/double_free)

- [House of Botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/house_of_botcake.c)

- [Leaking from stdout](https://vigneshsrao.github.io/posts/babytcache/)
 
# Brief explanation
 
The house of plastic-cake utilizes the house of botcake to generate an overlaped chunk, then a 3rd free of the same chunk  needs to be done in order to perform 2 writes: First, overwrite the las 2 bytes of the libc pointer generated in the unsorted bin to try to guess (1/16 chance) the stdout libc address. Second,it uses another write to point the FD of the already freed bug "forwards" on the heap to the modified libc address. This will trigger a leak, then, using the already double freed chunk (using the same overlap), or performing another house of botcake it generates a shell overwriting the free hook.
 
# Detailed explanation
 
 
This explanation is for glibc 2.29, for versions 2.28 and below less workaround is necessary since the [double free key field](https://blog.infosectcbr.com.au/2019/09/linux-heap-glibc-tcache-double-free.html) mitigations was introduced on 2.29 so it should be easy to follow for that version also. The steps are the follow:
 
1.- Generate a house of botcake situation, using sizes larger than the fastbin range, I will use  0xa0 in this example and it is what I recommend to try first. so,  generate 7 chunks of that size, a "prev” chunk, then a victim chunk or chunk "a" as mentioned in the original [house of botcake publication](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/house_of_botcake.c). after that you can request any size  chunk as "guard" to avoid consolidation. I recommend to insert the "/bin/sh/\x00" string cause we can use that chunk to later on free it when the free hook is overwritten with the system address then you need to free the first chunks, free "a", free "prev", request a 0xa0 chunk to empty on tcache bin and repeat the amount of times you need to have an extra free chunk in this case one more, and then free "a" again to generate a double free:

Example:
```python
for i in range(7):
    malloc(0x98, "A")

prev = malloc(0x98, "B")
a = malloc(0x98, "C")
guard = malloc(0x18, b"/bin/sh\x00")

for i in range(7):
    free(i)
free(a)
free(prev)
b = malloc(0x98, "AAAAAAAA") 
c = malloc(0x98, "YYYYYYYY")
##double free
free(a)
```
 
2.- Request a chunk that overlaps the already double freed chunk as in the house of botcake, in this case I will  use a 0xc0 size chunk keeping the same 0xa1 (in this case) size of the freed chunk, but zeroing the FD and BK (key field) of the freed chunk in the way of the overlapped one. this is to overcome the double free mitigation that it will check if the address of the tcache struct is written on the "bk" of the freed chunk as key. we zeroit so we can freed again and generate a new DF situation.

Example:
```python
malloc(0xb8, p64(0)*19 +p64(0xa1)+p64(0)*2)
```

3.- We free the chunk to generate the freed chunk on the tcache 0xa0 and now we free overlapped chunk 0xc0.
 

4.- Request a 0xa0 chunk again to being served from the overlapped chunk and overwrite the size of the unsorted bin in this case should be 0x81, or the size that you got and the just overwrite the last 2 bytes of the libc pointer in the FD of the unsortedbin. This will be our 1/16 brute force of the stdout address

Example:
```python
malloc(0x98, p64(0)*3 +p64(0x81)+p16(0x1760))
```

5.- Now this is the tricky part, you need to now request another 0xc0 chunk that overlaps the chunk that you just allocate (that is also free) and keep the size (0xa1) and then modify the last byte of the FD to point to where the libc pointers that we modified are, this should be 0x20 bytes ahead, if not you just need to adjust the value according to the sizes you request, but the value should be fixed if you keep the consistency on the sizes. 

```python
malloc(0xb8, p64(0)*19+p64(0x91)+p8(0x80))# 0x80 is modified to point forwards in the heap where the overwritten libc point is
```
 
6.- Then Request 2 malloc to clear the tcachebin list, and the the chunk will be served from the stdout address, using the technique described [here](https://vigneshsrao.github.io/posts/babytcache/) you will get a leak, even when the binary does not have any read function
 
7.- You can now repeat the steps of the house of botcake to create an overlapped chunk, but this time you can modify the FD of the overlapped chunk in the tcache with the address of the free hook
 
8.- Request a 0xa0 chunk to write the free hook in the tcache struct for the 0xa0 chunks
 
9.- Request a 0xa0 chunk that will be served from the free hook, and write the system address
 
10.- Free the guard chunk, or the chunk where you write your command "/bin/sh\x00"
 
# Conclusion

I really enjoy heap exploitation and this exercise help me a lot to better understand malloc internals. I wouldn't really called a "house" but its a nice approach to exploit double free bugs that have more restrctions, I hope this post is useful to more poeple that want top explore the heap internals. If you have any doubts about this post you can contact me at dicord dplastico#3901

I wanted to thanks the people that help me to write this post:

[c4e](https://c4ebt.github.io/) an amazing pwner and friend that is always in the mood to help.

Max Kamper creator of [Ropemporium](https://ropemporium.com/) who I want to thank for everything he has taught me about Heap
