---
layout: post
title: Como funciona una transferencia de zona?
date: 2019-04-17 21:30
comments: true
categories: [Sin categoría, transferencia de zona, zone transfer]
---
<!-- wp:paragraph -->
<p>Muchas veces trabajando en seguridad escuchamos de,  o derechamente ejecutamos una transferencia de zona para enumerar o buscar subdominios a partir de un DNS server que descubrimos, pero que hace realmente una transferencia de zona, cual es la utilidad de la misma? Por que la encontramos habilitada?</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Tratemos entonces de definir una transferencia de zona: </p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Transferencia de zona (<a href="https://tools.ietf.org/html/rfc5936">RFC 5936</a>) es un tipo de transacción DNS (sistema de nombres de dominio, el cual traduce y/o apunta cada dominio a la IP correspondiente) normalmente inducida a través de una consulta tipo “AXFR” para poder replicar bases de datos con registros entre servidores DNS.</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Como opera: La idea detrás de todo esto, como podrán haberse dado cuenta, es mantener consistencia entre dos o mas servidores DNS, o sea generar concordancia entre un registro DNS en un servidor "primario" y servidores "secundarios" los cuales se  actualizan consultando cambios al servidor "primario" para así actualizar sus registros propios, de esta manera cualquier cambio realizado en el servidor DNS principal se replica hacia el resto de servidores.</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Entonces como funciona esta replica de registros?</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Cada transferencia AXFR, dependiendo de la cantidad de registro, puede tener un numero importante de Datos, por lo que actualizar los registros puede generar mucho trafico por lo mismo antes de enviar un "request" AXFR el en este caso cliente (servidor secundario) envía un "request" de SOA (start of authority) a lo cual el servidor responde con un "SOA record" el cual contiene información sobre la zona consultada y es usado por el cliente para determinar si requiere enviar un posterior "request" AXFR para actualizar sus registros. este "request" de SOA se realiza por el puerto 53, y puede ser una conexión tipo TCP o UDP</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Luego de esto es que el cliente inicia un requerimiento AXFR, el cual se realiza a través de una conexión TCP al mismo puerto</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":90,"align":"left"} -->
<div class="wp-block-image"><figure class="alignleft"><img src="/wp-content/uploads/2019/04/zonexfer-1.gif" alt="" class="wp-image-90" /></figure></div>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Por lo tanto al hacer una transferencia de zonas lo que hacemos es pedir un SOA y luego un requerimientio AXFR, ante lo cual el servidor nos responderá con una actualización y el detalle de IP y dominio de cada registro que mantenga en su base de datos. Por esta misma razón es importante el mantener los servidores DNS configurados correctamente, para que por ejemplo solo puedan recibir "requests" AXFR de ip determinadas, crear reglas en firewall y/o similares, etc.</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>La información contenida en cada transferencia de zona puede entregarnos la información de todos los dominios y/o servidores de cada base de datos de registros en el servidor DNS, lo cual puede llevar a fugas de información importantes, especialmente en la parte de reconocimiento de un ataque, es importante limitar o restringir la transferencia de zonas ya que este mecanismo permite a un atacante recolectar información importante</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Para mayor información y detalle:</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><a href="http://cr.yp.to/djbdns/axfr-notes.html">http://cr.yp.to/djbdns/axfr-notes.html</a></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><a href="https://en.wikipedia.org/wiki/DNS_zone_transfer">https://en.wikipedia.org/wiki/DNS_zone_transfer</a></p>
<!-- /wp:paragraph -->

<!-- wp:core-embed/wordpress {"url":"http://systemadmin.es/2008/12/como-solicitar-una-transferencia-de-zona-mediante-dig","type":"wp-embed","providerNameSlug":"systemadmin-es","className":""} -->
<figure class="wp-block-embed-wordpress wp-block-embed is-type-wp-embed is-provider-systemadmin-es"><div class="wp-block-embed__wrapper">
http://systemadmin.es/2008/12/como-solicitar-una-transferencia-de-zona-mediante-dig
</div></figure>
<!-- /wp:core-embed/wordpress -->

<!-- wp:paragraph -->
<p></p>
<!-- /wp:paragraph -->
