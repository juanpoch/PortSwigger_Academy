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
Observamos que el parámetro `test` es reflejado sin una correcta sanitización dentro del atributo `href` de una etiqueta `<link rel="canonical">`.

## 🔗 Canonical Links

Un **Canonical Link** es una etiqueta HTML usada para decirle a los motores de búsqueda **cuál es la versión principal o "canónica" de una página web** cuando existen varias versiones con contenido similar o duplicado.

Se ve así:

```html
<link rel="canonical" href="https://example.com/articulo-principal">
 ```
En nuestro caso, estaríamos viendo que el **canonical link** no está siendo bien implementado, ya que la url se construye dinámicamente, y es allí donde reside la vulnerabilidad..


Vemos que la url se inserta dinámicamente en el código fuente (y no únicamente en el `DOM`) y vemos que se inserta entre comillas simples:
![image](https://github.com/user-attachments/assets/1d0d2620-1d74-445a-8e85-fb7a19b36c25)


Otros vectores son posibles si podemos romper la cadena de texto actual usando `'` e ingresar un atributo después:

![image](https://github.com/user-attachments/assets/edcf2209-8051-4f83-9724-b965a643c5eb)
