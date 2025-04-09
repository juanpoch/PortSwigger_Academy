# Lab: Reflected XSS in canonical link tag

This lab reflects user input in a canonical link tag and escapes angle brackets.

To solve the lab, perform a cross-site scripting attack on the home page that injects an attribute that calls the `alert` function.

To assist with your exploit, you can assume that the simulated user will press the following key combinations:

- ALT+SHIFT+X
- CTRL+ALT+X
- Alt+X
Please note that the intended solution to this lab is only possible in Chrome.

---

- `Nota`: [XSS in hidden input fields - PortSwigger](https://portswigger.net/research/xss-in-hidden-input-fields)

Ingresamos una cadena arbitraria en la cadena de consulta y observamos el `DOM`:
![image](https://github.com/user-attachments/assets/c9574f8a-f911-48e8-b06f-2e9cf6475658)

Podemos observar que entre las etiquetas `<head>` se inserta nuestra url dinámicamente.

Puntualmente observamos lo siguiente:
```html
<head>
...
<link rel="canonical" href="https://0a4500960436e24dc42788af00700029.web-security-academy.net/?test">
...
</head>
```
Observamos que el parámetro `test` es reflejado sin una correcta sanitización dentro del atributo `href` de una etiqueta `<link rel="canonical">`. Aunque los caracteres como `<` y `>` están escapados (angle brackets HTML-encoded), otros vectores son posibles si podemos romper la cadena de texto actual e ingresar un atributo después:

