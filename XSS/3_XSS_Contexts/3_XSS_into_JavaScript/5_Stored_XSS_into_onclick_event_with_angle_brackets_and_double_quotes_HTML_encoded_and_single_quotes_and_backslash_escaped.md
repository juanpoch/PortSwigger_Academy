# Lab: Stored XSS into `onclick` event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped

This lab contains a stored cross-site scripting vulnerability in the comment functionality.

To solve this lab, submit a comment that calls the `alert` function when the comment author name is clicked.

---

Nos encontramos con una página que nos permite realizar un comentario.

Realizamos un comentario de prueba para ver si hay reflexión de nuestros inputs:
![image](https://github.com/user-attachments/assets/485924f2-fdc1-4479-a4fa-3cfe75af9c71)

```html
<a id="author" href="https://test.com" onclick="var tracker={track(){}};tracker.track('https://test.com');">nombre</a>
```

### 🔍 Análisis del código línea por línea:
1. `<a id="author" href="https://test.com" ... >nombre</a>`
- Es un enlace `HTML` con:
  - `id="author"`: un identificador único para este elemento.
  - `href="https://test.com"`: si el usuario hace clic en este enlace, lo redirige a `https://test.com`.
  - Texto del enlace: `nombre`.
2. `onclick="var tracker={track(){}};tracker.track('https://test.com');"`
- Esto es un evento JavaScript `onclick`. Se ejecuta al hacer clic en el enlace.
- Dentro del `onclick`:
  ```js
  var tracker = { track(){} };
  tracker.track('https://test.com');
  ```
  - Se define una variable `tracker` como un objeto con un método `track`.
  - Luego se llama a ese método: `tracker.track('https://test.com')`.
  - ⚠️ Pero el método está vacío (`{}`), o sea, no hace nada actualmente.

Vemos que nustra url `https://test.com` se refleja en el atributo `href` y además dentro del método `track` de la variable `tracker`: `tracker.track('https://test.com')`


  



