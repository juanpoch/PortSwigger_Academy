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

---

## Ataques SSRF contra el servidor y sistemas internos

### Por qué las aplicaciones confían en solicitudes locales

En muchas arquitecturas web, se asume erróneamente que **las solicitudes provenientes del propio servidor son seguras**. Esta suposición abre la puerta a las vulnerabilidades SSRF. Veamos algunos motivos comunes por los cuales una aplicación puede comportarse de esta manera:

* **Controles de acceso en capas externas**: Algunas veces, la lógica que valida si un usuario puede acceder a una URL determinada no está implementada dentro de la aplicación, sino en un componente externo (por ejemplo, un WAF, proxy inverso o firewall). Cuando la aplicación hace una petición a sí misma, estos controles pueden ser evitados porque la conexión no pasa por esos intermediarios.

* **Recuperación ante desastres (Disaster Recovery)**: Para permitir que un administrador pueda recuperar el sistema si pierde el acceso, algunas aplicaciones permiten acceder a la interfaz administrativa desde localhost sin autenticación. Esta decisión se basa en la suposición de que nadie podría originar una solicitud desde dentro del propio servidor salvo un usuario legítimo.

* **Puertos diferentes para interfaces críticas**: A veces, la interfaz de administración se encuentra en otro puerto distinto al de la aplicación pública, y se cree que al no estar expuesto directamente a internet, está protegido. Sin embargo, si un atacante puede forzar al servidor a hacer solicitudes internas, este aislamiento por puerto se vuelve inútil.

Estas "relaciones de confianza implícitas" entre servicios internos son exactamente lo que hacen que **una vulnerabilidad SSRF se convierta en una amenaza crítica**.

### Ataques SSRF contra sistemas back-end internos

Más allá de explotar recursos locales (localhost), un atacante puede usar SSRF para interactuar con otros sistemas internos de la red que **no son accesibles desde el exterior**. Estos sistemas suelen tener direcciones IP privadas, como:

* `192.168.x.x`
* `10.x.x.x`
* `172.16.x.x` a `172.31.x.x`

Dado que estos sistemas están protegidos por la topología de red (segmentación), muchas veces tienen **controles de seguridad mínimos o nulos**, bajo el supuesto de que no serán accesibles desde el exterior. Sin embargo, si la aplicación vulnerable puede interactuar con ellos, un atacante puede aprovechar esto para:

* Acceder a paneles administrativos internos.
* Obtener información sensible.
* Ejecutar acciones como borrar registros, reiniciar sistemas, u otras funciones críticas.

#### Ejemplo práctico:

Supongamos que una aplicación vulnerable permite especificar la URL desde donde obtener stock, mediante el parámetro `stockApi`. El atacante envía:

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://192.168.0.68/admin
```

Si el servidor puede hacer solicitudes internas y no hay controles de validación estrictos, esta solicitud **forzará al servidor a acceder al panel administrativo interno ubicado en `192.168.0.68`**, devolviendo su contenido al atacante.

#### Posibles objetivos dentro de la red interna:

* APIs de gestión (`http://192.168.1.1/api/config`)
* Consolas de bases de datos (`http://10.0.0.5/phpmyadmin`)
* Servicios de monitorización (`http://localhost:3000/`)
* Instancias de cloud metadata (`http://169.254.169.254/latest/meta-data/`)

Estas interfaces suelen devolver **datos sensibles o tokens** que permiten escalar privilegios dentro de la infraestructura.

### Importancia de validar correctamente

Este tipo de ataques demuestra que **confiar en IPs internas o nombres como `localhost` no es una medida de seguridad válida**. Las aplicaciones deben:

* Validar estrictamente las URLs recibidas del cliente.
* Implementar listas blancas (whitelists) de destinos permitidos.
* Restringir el acceso del servidor a direcciones internas si no es necesario.

---

A continuación veremos un laboratorio práctico que permite explotar un SSRF contra un sistema interno basado en una dirección IP privada.

[Lab: Basic SSRF against another back-end system](2_Basic_SSRF_against_another_back-end_system.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 
