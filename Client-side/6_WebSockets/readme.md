# Testing de vulnerabilidades de seguridad en WebSockets

## 🔗 WebSockets

Los **WebSockets** son ampliamente utilizados en aplicaciones web modernas para habilitar una comunicación bidireccional y asincrónica entre el cliente y el servidor. A diferencia del modelo clásico HTTP basado en petición-respuesta, los WebSockets permiten mantener una conexión persistente en la que ambas partes pueden enviar mensajes en cualquier momento.

Esto los hace ideales para:
- Chats en tiempo real
- Actualizaciones de precios en vivo
- Juegos online
- Monitoreo en tiempo real

No obstante, **esta flexibilidad también introduce vectores de ataque** y requiere una atención especial en auditorías de seguridad.

---

## ❓ ¿Qué son los WebSockets?

> **WebSocket** es un protocolo full-duplex, bidireccional y persistente, iniciado sobre HTTP, que permite el intercambio de mensajes sin la sobrecarga de una nueva conexión por cada mensaje.

### Diferencias clave entre HTTP y WebSockets

| Característica         | HTTP                       | WebSocket                        |
|------------------------|----------------------------|----------------------------------|
| Modelo                 | Petición / Respuesta       | Conexión persistente             |
| Quién inicia           | Cliente                    | Cualquiera (cliente o servidor)  |
| Estado de la conexión | Corta tras la respuesta     | Permanece abierta                |
| Utilidad               | Navegación clásica, APIs   | Chat, juegos, updates en tiempo real |

---

## 🔄 Establecimiento de conexión

Una conexión WebSocket se inicia desde el navegador mediante JavaScript:

```js
var ws = new WebSocket("wss://normal-website.com/chat");
```

- `ws://` establece una conexión sin cifrado.
- `wss://` establece una conexión cifrada sobre TLS (como HTTPS).

### Handshake WebSocket

Este handshake se realiza sobre HTTP:

#### Solicitud del cliente
```http
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
```

#### Respuesta del servidor
```http
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```

✅ Tras este intercambio, la conexión queda abierta y lista para enviar/recibir mensajes.

---

## 📉 Estructura de un mensaje WebSocket

Una vez establecida la conexión, se pueden enviar mensajes con:

```js
ws.send("Hola mundo");
```

Es común utilizar JSON como formato de intercambio:

```json
{"user":"Juan","message":"Hola desde el cliente"}
```

---

## ⚖️ Manipulación de tráfico WebSocket con Burp Suite

Burp Suite permite interceptar, modificar y reproducir mensajes WebSocket.

### ✏️ Interceptar y modificar
1. Abrí Burp Browser.
2. Navegá hasta la funcionalidad que utiliza WebSockets.
3. Activá la intercepción desde la pestaña **Proxy > Intercept**.
4. Los mensajes WebSocket aparecerán en **Proxy > WebSockets**.

### ↺ Repetir y generar nuevos mensajes
- Seleccioná un mensaje y hacé clic derecho: **"Send to Repeater"**.
- Desde **Repeater**, podés editar y reenviar el mensaje.
- También podés crear nuevos mensajes desde cero.

### ✍️ Manipular la conexión WebSocket
1. En Repeater, hacé clic en el ícono de lápiz junto a la URL.
2. Elegí "Clone" o "Reconnect" para editar el handshake inicial.
3. Podés modificar cabeceras como `Sec-WebSocket-Key` o `Cookie` antes de conectar.

---

## 🔒 Vulnerabilidades comunes en WebSockets

Las mismas vulnerabilidades clásicas de HTTP también pueden aparecer en WebSockets:

- **SQL Injection / NoSQL Injection**
- **XSS (Cross-Site Scripting)**
- **XXE (XML External Entity)**
- **OAST (Out-of-band attacks)**

### Ejemplo de XSS por WebSocket

Supongamos que un mensaje WebSocket como:
```json
{"message":"Hola Carlos"}
```
es reflejado sin sanitización como:
```html
<td>Hola Carlos</td>
```
Un atacante podría enviar:
```json
{"message":"<img src=1 onerror='alert(1)'>"}
```
y provocar una ejecución de código arbitrario en el navegador de otro usuario.

---

## 🔍 Checklist de testing en WebSockets

- [ ] ¿Se puede interceptar el handshake y modificar cookies/tokens?
- [ ] ¿Los mensajes permiten inyecciones de entrada no validadas?
- [ ] ¿Hay reflejo de datos en el cliente (XSS)?
- [ ] ¿Se puede enviar mensajes sin autenticación?
- [ ] ¿Se puede forzar al servidor a enviar respuestas inesperadas?

---

## 🔗 Recursos recomendados

- [MDN WebSockets](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket)
- [RFC 6455 - The WebSocket Protocol](https://datatracker.ietf.org/doc/html/rfc6455)
- [PortSwigger: WebSockets vulnerabilities](https://portswigger.net/web-security/websockets)
- [Burp Suite Docs - WebSockets](https://portswigger.net/burp/documentation/desktop/tools/repeater/websockets)

---

## 📊 Tip extra para pentesters

En entornos productivos, es común que el tráfico WebSocket se combine con tokens CSRF, JWT o cabeceras personalizadas. Analizá si los mensajes pueden ser replicados sin el token o si podés manipular el handshake para **reutilizar o escalar privilegios**.

---

💡 **Continuar**: [Laboratorio 1 - WebSocket XSS reflejado](#)
