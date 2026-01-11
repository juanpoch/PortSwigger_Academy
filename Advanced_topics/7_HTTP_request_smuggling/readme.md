# HTTP request smuggling | Client-Side Desync

# HTTP Request Smuggling

## Introducción

**HTTP Request Smuggling** es una técnica de ataque que permite interferir con la forma en que una aplicación web procesa **secuencias de solicitudes HTTP**. Este tipo de vulnerabilidad suele ser **crítica**, ya que puede permitir:

* Bypass de controles de seguridad
* Acceso no autorizado a información sensible
* Compromiso directo de otros usuarios de la aplicación

El ataque se basa en provocar **desincronización (desync)** entre distintos servidores HTTP que procesan una misma conexión.

---

## Contexto arquitectónico

En aplicaciones web modernas es muy común encontrar una **cadena de servidores HTTP**, por ejemplo:

```
Cliente → Front-end (Load Balancer / Reverse Proxy) → Back-end (Aplicación)
```

El front-end recibe las peticiones del usuario y las **reenvía** al back-end. Para mejorar el rendimiento, estas peticiones suelen enviarse **una detrás de otra sobre la misma conexión TCP**.

Esto implica que el servidor receptor debe determinar correctamente:

* Dónde termina una request
* Dónde comienza la siguiente

Si **front-end y back-end no coinciden** en cómo interpretar los límites de una request, se genera la vulnerabilidad.

---

## ¿Qué ocurre en un ataque de Request Smuggling?

En un ataque exitoso:

* El atacante envía una request **ambigua**
* El front-end la interpreta de una manera
* El back-end la interpreta de otra

Parte de la request del atacante es interpretada por el back-end como el **inicio de la siguiente request**, quedando "inyectada" o **smuggled**.

Esto permite manipular el flujo normal de solicitudes y afectar a requests legítimas de otros usuarios.

---

## Origen de la vulnerabilidad

La mayoría de las vulnerabilidades de HTTP request smuggling surgen debido a que **HTTP/1 ofrece dos mecanismos distintos para definir el fin de una request**:

### 1. Content-Length

Indica el tamaño del body en bytes.

Ejemplo:

```
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

El servidor lee exactamente 11 bytes como cuerpo.

---

### 2. Transfer-Encoding: chunked

Indica que el body se envía en **chunks**.

Formato:

* Tamaño del chunk en hexadecimal
* Salto de línea
* Contenido
* Chunk final de tamaño 0

Ejemplo:

```
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b
q=smuggling
0
```

---

## Por qué esto genera problemas

El estándar HTTP/1 indica que:

> Si están presentes `Content-Length` y `Transfer-Encoding`, se debe ignorar `Content-Length`.

Esto **funciona con un solo servidor**, pero **falla en arquitecturas encadenadas**, porque:

* Algunos servidores **no soportan** `Transfer-Encoding` en requests
* Otros pueden ser inducidos a **ignorar el header** si está ofuscado

Si front-end y back-end procesan headers distintos, **no coinciden en los límites de la request**, habilitando el ataque.

---

## HTTP/1 vs HTTP/2

* **HTTP/1**: vulnerable a request smuggling
* **HTTP/2 end-to-end**: inherentemente inmune

HTTP/2 define un único mecanismo robusto para delimitar requests, eliminando la ambigüedad.

⚠️ Importante:

Muchas aplicaciones usan:

```
Cliente (HTTP/2) → Front-end → Back-end (HTTP/1)
```

Este proceso se llama **HTTP downgrading** y puede reintroducir vulnerabilidades.

---

## Tipos clásicos de Request Smuggling

Los ataques clásicos combinan `Content-Length` y `Transfer-Encoding` en una misma request HTTP/1.

Dependiendo de qué header use cada servidor, se clasifican en:

### CL.TE

* Front-end usa `Content-Length`
* Back-end usa `Transfer-Encoding`

### TE.CL

* Front-end usa `Transfer-Encoding`
* Back-end usa `Content-Length`

### TE.TE

* Ambos soportan `Transfer-Encoding`
* Uno de ellos puede ser engañado para ignorarlo mediante ofuscación

---

## Consideraciones prácticas de testing

* Los navegadores **no usan chunked encoding** en requests
* Burp Suite **desempaqueta automáticamente** chunked encoding
* Burp y navegadores usan **HTTP/2 por defecto** si el servidor lo soporta

➡️ Para testear request smuggling:

* Es necesario **forzar HTTP/1** manualmente en Burp Repeater

---

## Vulnerabilidad CL.TE (caso básico)

En este escenario:

* El front-end confía en `Content-Length`
* El back-end confía en `Transfer-Encoding`

### Ejemplo de request maliciosa

```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### Interpretación

**Front-end**:

* Lee 13 bytes de body
* Considera que todo es una sola request
* La reenvía al back-end

**Back-end**:

* Procesa `Transfer-Encoding: chunked`
* Ve un chunk de tamaño 0 → fin de request
* El contenido `SMUGGLED` queda pendiente

Ese contenido es interpretado como el **inicio de la siguiente request**.

---

## Primer laboratorio

**HTTP request smuggling – basic CL.TE vulnerability**

Objetivo:

* Identificar una desincronización CL.TE
* Confirmar que el back-end procesa el payload smuggled como una nueva request

Este laboratorio sirve como **base conceptual** para todos los ataques avanzados de request smuggling.

---

> Este documento cubre la introducción completa hasta el primer laboratorio de la sección HTTP Request Smuggling de PortSwigger.

