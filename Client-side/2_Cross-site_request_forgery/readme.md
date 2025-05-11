# Cross-Site Request Forgery

## 🔎 ¿Qué es CSRF?

**Cross-Site Request Forgery** es una vulnerabilidad de seguridad web que permite a un atacante inducir a un usuario autenticado a realizar acciones que no tenía intención de ejecutar. En esencia, **aprovecha la confianza que un sitio tiene en el navegador del usuario**.

El ataque CSRF permite en parte eludir la **Same Origin Policy**, una política de seguridad que impide que sitios distintos se interfieran entre sí.

---

## 🚀 Impacto de un ataque CSRF

Cuando un CSRF tiene éxito, el atacante puede:

* Cambiar la dirección de correo del usuario.
* Modificar su contraseña.
* Transferir fondos.
* Realizar cualquier acción que el usuario autenticado pueda ejecutar.

Si el usuario víctima tiene privilegios elevados, como un administrador, el atacante podría obtener control total sobre la aplicación.

---

## ⚖️ Requisitos para que un CSRF sea posible

Para que una vulnerabilidad CSRF pueda explotarse, deben cumplirse tres condiciones:

1. **Acción relevante**: Debe existir una acción que interese al atacante (por ejemplo, cambio de contraseña, email, etc.).
2. **Manejo de sesión basado en cookies**: El sitio usa **cookies automáticas** para identificar al usuario, sin ningún otro mecanismo adicional de validación (como tokens).
3. **Parámetros predecibles**: El atacante puede predecir o controlar los parámetros necesarios en la solicitud HTTP.

---

## 📁 Ejemplo de solicitud vulnerable

```
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=abc123xyz

email=attacker@example.com
```

Si el servidor solo depende de la cookie para autenticar la sesión y no requiere token, es vulnerable.

---

## 🔧 Construcción de un ataque CSRF

El atacante puede crear una página HTML maliciosa como esta:

```html
<html>
  <body>
    <form action="https://vulnerable-website.com/email/change" method="POST">
      <input type="hidden" name="email" value="pwned@evil-user.net">
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```
Este fragmento de código representa una prueba de concepto para explotar una vulnerabilidad de tipo **Cross-Site Request Forgery**. A continuación se detalla el funcionamiento de cada parte del documento y su implicancia en el ataque.

---

## 🔍 Contexto general

La página fue creada por un atacante con el objetivo de inducir a un usuario autenticado a **enviar una solicitud POST maliciosa** al sitio `vulnerable-website.com`, sin que el usuario lo sepa.

El objetivo es cambiar el email de la cuenta del usuario víctima por `pwned@evil-user.net`.

---

## 🗋 Estructura del HTML

```html
<html>
    <body>
        <form action="https://vulnerable-website.com/email/change" method="POST">
            <input type="hidden" name="email" value="pwned@evil-user.net" />
        </form>
        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

### ✉️ Formulario oculto

```html
<form action="https://vulnerable-website.com/email/change" method="POST">
    <input type="hidden" name="email" value="pwned@evil-user.net" />
</form>
```

* El formulario está configurado para enviar una solicitud POST a `https://vulnerable-website.com/email/change`.
* El campo `email` tiene un valor oculto (`hidden`) que representa el correo malicioso al que el atacante quiere cambiar la cuenta del usuario.
* Este formulario no tiene botones visibles para el usuario.

### 👉 Envió automático con JavaScript

```html
<script>
    document.forms[0].submit();
</script>
```

* Apenas se carga la página, el navegador ejecuta este script.
* El script selecciona el primer formulario de la página (`forms[0]`) y lo **envía automáticamente**.
* Si el usuario está logueado en `vulnerable-website.com`, su navegador enviará también la cookie de sesión.

---

##

---

Si el usuario víctima visita esta página mientras está autenticado en el sitio vulnerable:

* Su navegador enviará la cookie de sesión.
* El servidor procesará la petición como si el usuario la hubiese enviado.

---

## ✨ Automatización del ataque con Burp Suite

Burp Suite Professional permite generar ataques CSRF de forma automática:

1. Seleccionar una petición en Burp.
2. Clic derecho → **Engagement tools** → **Generate CSRF PoC**.
3. Burp genera el HTML necesario para explotar el CSRF.
4. Se puede editar para afinar el ataque.

Esto simplifica la creación de formularios con muchos parámetros o requests complejos.

---

## 🌐 Mecanismos de entrega de CSRF

* **HTML alojado por el atacante**: se envía por redes sociales, email, etc.
* **Comentario en sitio popular**: donde se incluya el HTML malicioso.
* **Autoejecución con `img src`** si la acción vulnerable es por GET:

```html
<img src="https://vulnerable.com/deleteUser?id=123">
```

No se necesita formularios en este caso, y puede ejecutarse con solo visitar una URL.

---

## 🛡️ Defensas contra CSRF

### 1. CSRF tokens

* Valor secreto e impredecible que el servidor incluye en formularios.
* El cliente debe reenviarlo en cada solicitud.
* Si falta o es incorrecto, se bloquea la acción.

### 2. SameSite cookies

* Evita el envío de cookies en requests cross-site.
* Desde 2021, **Chrome aplica SameSite=Lax** por defecto.
* SameSite=Strict ofrece mayor protección.

### 3. Validación Referer/Origin

* El servidor verifica que el origen de la petición coincida con el dominio válido.
* Más fácil de evadir que un CSRF token.

---

## 🔗 Recursos adicionales

* [CSRF Labs en PortSwigger Academy](https://portswigger.net/web-security/csrf)
* [SameSite cookies (Google Dev)](https://developer.chrome.com/docs/web-platform/samesite-cookies-explained/)
* [CSRF Prevention Cheat Sheet - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

---

## 🎓 Conclusiones clave

* CSRF explota el comportamiento automático de los navegadores al enviar cookies.
* Las solicitudes GET y POST son vulnerables si no hay protección.
* Las defensas modernas (tokens, SameSite, CSP) dificultan su explotación.
* Aun así, muchos sitios implementan protecciones mal configuradas.

---

