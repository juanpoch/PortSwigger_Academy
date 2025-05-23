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

Por lo tanto el escenario es el siguiente, podríamos intentar inyectar en estos dos sitios de reflexión:
- Podríamos intentar hacer un break out en `href` insertando `"` y especificar nuestro propio atributo.
- Inyectar `<script>` tags, abrir un `javascript:` y ejecutar la función `alert`.
- Intentar hacer un break out de la cadena javascript que le estamos pasando a la función `tracker` utilizando comilla simple `'`.

El problema es que como dice el laboratorio, muchos caracteres como `<>`, `"` están siendo html encodeados y `'` o `\` están siendo escapados.

`Ejemplo`:
Intentaremos realizar un `break out` de las cadenas que le pasamos como argumento a la función `tracker`:
![image](https://github.com/user-attachments/assets/644fdf23-2076-4305-bb72-de96c25742ab)

Aquí estaríamos inyectando lo siguiente:
```js
tracker.track('https://test.com' + alert() + '')
```

Aquí estamos realizando una concatenación (no estamos pasando distintos argumentos, por eso no se separa con `,`).
En este caso, al realizar la concatenación, primero se ejecuta `alert()` que retorna undefined y luego se ejecuta la concatenación.

En este caso vemos que escapa la `'`:
![image](https://github.com/user-attachments/assets/f8bbc98f-3b18-45da-97be-8363b8674526)


Es altamente probable que los desarrolladores hayan realizado una sanitización "manual" de estos caracteres, y es posible que pueda usarse como input valores `html encoded`.

Vamos a pasar la siguiente cadena en el campo Website:
```html
https://test.com?&apos;-alert(1)-&apos;
```
`Nota`: El caracter `?` no es estrictamente necesario en este caso.

![image](https://github.com/user-attachments/assets/37326e4a-19e1-4d19-9947-7841aad816ef)

Y nuestro resultado es que resolvemos el lab:
![image](https://github.com/user-attachments/assets/e6ba51bc-660b-4487-8541-c73139ac438e)
![image](https://github.com/user-attachments/assets/3c0f2584-056d-442c-9fed-0181ab669f5d)

### 🔐 Usando entidades HTML

En este escenario de inyección, aprovechamos que estamos dentro de un **atributo HTML**, como `onclick`.

Esto es importante porque en este contexto:

1. El **parser HTML** es el primero en actuar.
2. Este parser **convierte entidades como `&apos;` en comillas simples (`'`)**, antes de que el navegador ejecute el contenido del atributo como JavaScript.
3. Gracias a eso, podemos **inyectar comillas y otras estructuras peligrosas de forma segura**, sin romper el HTML.

➡️ Si estuviéramos en un contexto puramente JavaScript, como dentro de un archivo `.js` o una etiqueta `<script>`, el uso de `&apos;` no tendría ningún efecto: se interpretaría simplemente como texto literal.

---

### 🧩 ¿Cómo actúa el parser HTML?

Cuando el navegador recibe una página HTML, no la interpreta de golpe como un bloque de JavaScript. En su lugar:

1. **El parser HTML comienza a recorrer el código fuente** y construye una estructura interna conocida como el **DOM (Document Object Model)**.
2. Durante esta construcción:
   - Se identifican etiquetas (`<a>`, `<div>`, etc.)
   - Se procesan atributos (`href`, `onclick`, `src`, etc.)
   - **Y se decodifican las entidades HTML**, como:
     - `&lt;` → `<`
     - `&gt;` → `>`
     - `&quot;` → `"`
     - `&apos;` → `'`
3. Solo **después** de esta fase, se ejecutan los scripts y los atributos de eventos como `onclick`, ya con las entidades **traducidas** a sus caracteres reales.

Esto nos permite hacer algo como:

```html
<a onclick="tracker.track('https://test.com?&apos;-alert(1)-&apos;')">Click</a>
```
Que en realidad se interpreta como:
```js
tracker.track('https://test.com?'-alert(1)-'')
```
Lo cual rompe el contexto de cadena y ejecuta `alert(1)`.









  



