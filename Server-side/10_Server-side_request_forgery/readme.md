## 🧠 Server-Side Request Forgery 

---

### 🔎 ¿Qué es una vulnerabilidad SSRF?

La **Server-Side Request Forgery** es una vulnerabilidad de seguridad web que permite a un atacante manipular al servidor para que realice solicitudes HTTP (u otros protocolos) a ubicaciones no previstas o restringidas. En otras palabras, **el atacante logra que el servidor haga una solicitud en su nombre**, generalmente a recursos internos o protegidos.

A diferencia de un ataque convencional donde el atacante interactúa directamente con el recurso, en SSRF **el servidor vulnerable actúa como intermediario**. Esto puede dar lugar a filtración de datos internos, evasiones de controles de acceso, ataques a la infraestructura interna (intranet), o incluso ejecución remota de comandos en casos avanzados.

---

### 📊 Impacto de un ataque SSRF

Dependiendo del contexto y del entorno donde se explote, SSRF puede permitir:

* 🔐 Acceder a recursos internos (como `http://localhost`, `http://127.0.0.1`, `http://169.254.169.254` en AWS).
* 🔁 Enumerar y mapear servicios internos (DNS, Redis, etc.).
* 🌐 Realizar ataques hacia otros servidores externos, disfrazando el origen (Server-side proxying).
* ⚖️ Bypassear firewalls o controles de acceso (por ejemplo, acceder a `/admin`).
* ⚡️ Ejecutar comandos si se encadena con RCE.

---

### 🧨 Ejemplo clásico: SSRF contra el propio servidor

Imaginemos una aplicación que consulta información de stock desde un API backend mediante una URL proporcionada por el frontend:

```
POST /product/stock HTTP/1.1
Content-Type: application/x-www-form-urlencoded

stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=6&storeId=1
```

El servidor recibe la URL y hace una solicitud HTTP interna a ella. Pero el atacante puede modificar el parámetro:

```
stockApi=http://localhost/admin
```

Si la ruta `/admin` solo es accesible desde `localhost`, el atacante podría explotar esta confianza interna para obtener acceso privilegiado o extraer datos sensibles.

---

### ❌ Problemas comunes que permiten SSRF

* La aplicación **no valida correctamente la URL** proporcionada por el usuario.
* Se permite el control de **parámetros de direcciones o endpoints** sin verificar el destino.
* El servidor tiene **acceso a recursos internos** o servicios de metadatos (como `169.254.169.254` en entornos cloud).
* Los filtros de seguridad se basan solo en listas negras (blacklists), que pueden ser evadidas.

---

### ⚠️ Targets comunes de SSRF

* `http://127.0.0.1:80` o `http://localhost`: acceso a paneles administrativos internos.
* `http://169.254.169.254`: servidor de metadatos en AWS (puede revelar claves temporales de IAM).
* `http://internal-api` o dominios internos accesibles solo desde el servidor.
* Servicios de backend como Redis (`redis://localhost:6379`) o Gopher (`gopher://`).

---

### 🔍 Consejos para identificar SSRF

* Buscar funcionalidades que acepten URLs como input (fetch preview, webhooks, carga de recursos externos).
* Revisar solicitudes que interactúan con otras APIs o servicios mediante URLs.
* Observar diferencias en los tiempos de respuesta al usar direcciones internas o IPs reservadas.
* Probar si el servidor hace "reflejo" del contenido solicitado (indicador de que fue a buscar ese recurso).

---

### 🔧 Ejemplo de prueba simple

```http
POST /fetch HTTP/1.1
Host: vulnerable.com
Content-Type: application/x-www-form-urlencoded

url=http://127.0.0.1:80/admin
```

Resultado esperado: si `/admin` solo está disponible internamente, el servidor puede devolver el contenido al atacante, rompiendo los controles de acceso tradicionales.

---

[Lab: Basic SSRF against the local server](1_Basic_SSRF_against_the_local_server.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 


