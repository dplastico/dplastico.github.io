---
layout: post
title: Writeup, Juan el Hacker Q4 CTF 2019
date: 2019-09-02 02:12
comments: true
categories: [crypto, CTF, overflow, Q4, Sin categoría, writeup]
---
<!-- wp:paragraph -->
<p>Juan el hacker es una maquina que cree como desafio para el CTF Q4 2019, la maquina esta inspirada en la serie de animé Serial Experimentals Lain, Como veterano de los 90, esta serie me inspiro mucho y se la recomiendo a todos los que ven en la tecnología algo más que una herramienta. También puse algunas cosas ocultas con una pequeña historia, quienes resolvieron la maquina o avanzaron saben de lo que hablo, por lo mismo estos mensajes los dejo afuera para que haya algo de sorpresa jeje :)</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Volviendo a lo nuestro: Al enumerar usando nmap la maquina solo vemos algunos servicios abiertos:</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":104} -->
<figure class="wp-block-image"><img src="/wp-content/uploads/2019/09/image-1024x354.png" alt="" class="wp-image-104" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Revisando la web no se vé mucho, pero si llama la atención el puerto 79, un viejo protocolo (de los 90 jejeje) que era usado para mostrar información de tu user, esta información es normalmente proporcianada en archivos .plan y .project los cuales se guardan en el home del user, para más información.</p>
<!-- /wp:paragraph -->

<!-- wp:core-embed/wordpress {"url":"https://touhidshaikh.com/blog/?p=914","type":"wp-embed","providerNameSlug":"touhid-m-shaikh","className":""} -->
<figure class="wp-block-embed-wordpress wp-block-embed is-type-wp-embed is-provider-touhid-m-shaikh"><div class="wp-block-embed__wrapper">
https://touhidshaikh.com/blog/?p=914
</div></figure>
<!-- /wp:core-embed/wordpress -->

<!-- wp:paragraph -->
<p>Usando este servicio descubrimos que el usuario juan (como el nombre de la maquina) muestra lo siguiente:</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":105} -->
<figure class="wp-block-image"><img src="/wp-content/uploads/2019/09/image-1-1024x296.png" alt="" class="wp-image-105" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Copiamos el output del project que es claramente un Hex el cual al pasarlo a ASCII nos muestra un texto cifrado, el cual parece ser un rot o caesar cipher, por lo cual al decodearlo encontramos lo siguiente:</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":106} -->
<figure class="wp-block-image"><img src="/wp-content/uploads/2019/09/image-2-1024x328.png" alt="" class="wp-image-106" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Esto parece la primera parte de un password ya que no funciona por si solo, pero nos habla de un sitio oculto, esto nos ayuda a descifrar que hacer con el output que entrega plan, el cual parece un MD5, lo pasamos por un decrypter y encontramos "hola_lain"</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":107} -->
<figure class="wp-block-image"><img src="/wp-content/uploads/2019/09/image-3-1024x374.png" alt="" class="wp-image-107" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Con esto revisamos el sitio web y encontramos una pagina (hola lain, que también es una referencia a este animé</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":108} -->
<figure class="wp-block-image"><img src="/wp-content/uploads/2019/09/image-4-1024x579.png" alt="" class="wp-image-108" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>EL formulario es un html plano, pero al enumerar directorios dentro de hola_lain, podemos descubrir un directorio "admin" que tiene solo una foto</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":109} -->
<figure class="wp-block-image"><img src="/wp-content/uploads/2019/09/image-5.png" alt="" class="wp-image-109" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>la foto contiene un texto, sin contraseña usando steghide o similar, a gusto del participante se puede leer la segunda parte de la contraseña y formamos las credenciales para entrar como juan</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><em>juan:1missy0uch1saSt0pn0wchisa</em></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Una vez dentro como Juan debemos escapar una shell restringida usando el comando find , comparto esta pagina también con un link util y la forma de hacerlo</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><a href="https://www.hackplayers.com/2018/05/tecnicas-para-escapar-de-restricted--shells.html">https://www.hackplayers.com/2018/05/tecnicas-para-escapar-de-restricted--shells.html</a></p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":110} -->
<figure class="wp-block-image"><img src="/wp-content/uploads/2019/09/image-6-1024x503.png" alt="" class="wp-image-110" /></figure>
<!-- /wp:image -->

<!-- wp:image {"id":111} -->
<figure class="wp-block-image"><img src="/wp-content/uploads/2019/09/image-7-1024x392.png" alt="" class="wp-image-111" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Una vez ya dentro procedemos a enumerar,  y en el mismo directorio encontramos un archivo, que no se puede ejecutar, pero si podemos leerlo, por lo que procedemos a analizarlo y vemos los strings</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":112} -->
<figure class="wp-block-image"><img src="/wp-content/uploads/2019/09/image-8.png" alt="" class="wp-image-112" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>El código dice "if 5elemets: "BOFetada" Como un pequeño cameo al equipo con el que participé en la hackaton de telefónica y mi maquina favorita jejeje si probamos los strings como passwords vemos que el usuario lainiwakura puede entrar con la contraseña "BOFetada"</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":113} -->
<figure class="wp-block-image"><img src="/wp-content/uploads/2019/09/image-9.png" alt="" class="wp-image-113" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Ya dentro vemos claramente un archivo que llama la atención, es programa vulnerable a un buffer overflow de 32bit, que de hecho estudiando para el OSCE fue que me inspiré pensando en este exploit <a href="https://www.fuzzysecurity.com/exploits/7.html">https://www.fuzzysecurity.com/exploits/7.html</a></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Si quieren reproducirlo pueden usar este codigo en C:</p>
<!-- /wp:paragraph -->

<!-- wp:code -->
```C
#include &lt;stdlib.h&gt;
#include &lt;stdio.h&gt;
#include &lt;string.h&gt;
int lain(char *str)
{
        char buffer[24];
        

        strcpy(buffer, str);
        return 1;
}

int main(int argc, char **argv)
{
        char str[517];
        FILE *badfile;
        badfile = fopen("PHANTOMa", "r");
        fread(str, sizeof(char), 517, badfile);
        lain(str);
        printf("salimos bien juan, pero no queremos eso ... :( \n");
        return 1;

}
```
<!-- /wp:code -->

<!-- wp:paragraph -->
<p>Es algo mucho mas sencillo, es un simple exploit de 32 bit, al tener el stack ejecutable (perdonen por la mala compilación de los binarios en el CTF hjejeje, muchos perdieron tiempo en eso)</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Volviendo al exploit de chisa, nos damos cuenta que lee el input de el archivo PHANTOMa, cada vez que de ejecuta, por lo que debemos enviar ahi nuestro input</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":114} -->
<figure class="wp-block-image"><img src="/wp-content/uploads/2019/09/image-10-1024x73.png" alt="" class="wp-image-114" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Luego ejecutamos en gdb vemos que el EIP tiene un offset de 32, por lo que desde el byte dos en adelante podemos controlarlo, así que el plan es enviar un shellcode</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":115} -->
<figure class="wp-block-image"><img src="/wp-content/uploads/2019/09/image-11-922x1024.png" alt="" class="wp-image-115" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>El plan es enviar un shellcode, pero no cualquier shellcode, en sistemas nuevos, incluso usando 32, las shell como dash y bash tienen un mecanismo de seguridad que "dropea" cualquier privilegio de SUID antes de ejcutarse, por lo que un shellcode normal que llame a /bin/sh no nos servirá, es por eso que ocupamos python para poder ejecutar el shellcode como root y no "dropear" privilegios cuando se ejecute la shell.</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><a href="http://shell-storm.org/shellcode/files/shellcode-886.php">http://shell-storm.org/shellcode/files/shellcode-886.php</a></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Finalmente usamos este shellcode y copiamos el ouput del siguiente exploit a PHANTOMa (python exploit.py &gt; PHANTOMa)</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":116} -->
<figure class="wp-block-image"><img src="/wp-content/uploads/2019/09/image-12-1024x165.png" alt="" class="wp-image-116" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Y con esto tenemos una shell de root:</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":117} -->
<figure class="wp-block-image"><img src="/wp-content/uploads/2019/09/image-13-1024x370.png" alt="" class="wp-image-117" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Espero que les haya gustado!!</p>
<!-- /wp:paragraph -->
