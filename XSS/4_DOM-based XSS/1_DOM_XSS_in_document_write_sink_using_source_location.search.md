# Lab: DOM XSS in `document.write` sink using source `location.search`

This lab contains a DOM-based cross-site scripting vulnerability in the search query tracking functionality. It uses the JavaScript `document.write` function, which writes data out to the page. The `document.write` function is called with data from `location.search`, which you can control using the website URL.

To solve this lab, perform a cross-site scripting attack that calls the `alert` function.  


![Apprentice](https://img.shields.io/badge/Aprentice-%2300a86b?style=for-the-badge&logo=portainer&logoColor=white)


---

Tenemos un laboratorio que tiene la funcionalidad de búsqueada a través de una query string.

Realizamos una búsqueda de prueba para localizar dónde está siendo reflejada:
![image](https://github.com/user-attachments/assets/5bf2b581-28fb-4085-b442-5ecd54d99164)

Vemos la reflexión en 2 lugares distintos:
- Dentro de la etiqueta `<h1>`: Probablemente es parte de la respuesta que está enviando el servidor.
- Dentro de la etiqueta `<img>`: Esto tiene más probabilidad de estar siendo reflejado en el DOM.

![image](https://github.com/user-attachments/assets/1b4e2c5e-38b7-4fe6-8968-d4df4815302f)

Nótese cómo la reflexión en el código fuente se dá sólo entre las etiquetas `<h1>`, debido a que aun no se ejecutó JavaScript, la segunda reflexión sucede efectivamente en el DOM.


### Analizemos más detalladamente la segunda reflexión:

Tenemos unas etiquetas `<script>` que son las creadoras de la etiqueta `<img>` donde el parámetro se refleja:
```js
function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms=' + query + '">');
}

var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
    trackSearch(query);
}
```
# 🧠 Análisis por partes

## Fuente controlada por el usuario

```javascript
var query = (new URLSearchParams(window.location.search)).get('search');
```

Esto toma el parámetro `search` de la URL.

Es decir, si entrás a:

```
https://vulnerable-site.com/?search=abc123
```

→ `query` valdrá `"abc123"`.

---

## Sink vulnerable (`document.write`)

```javascript
document.write('<img src="/resources/images/tracker.gif?searchTerms=' + query + '">');
```

Este `query` se inyecta directamente en el HTML mediante `document.write()` sin sanitización.

Si el valor de `query` contiene código HTML o JavaScript, **se insertará en el DOM y el navegador lo ejecutará**.


El condicional es el encargado de llamar a la función trackSearch(query); si se pasa un parámetro para `query`.  

---

Debido a que la reflexión se dá dentro de la etiqueta `img`, dentro del atributo `src`, procedemos a realizar un break out y salirnos del atributo, cerrándolo y añadiendo un nuevo atributo.

Ingresamos el siguiente payload:

```js
abc123xy" onload="alert(1)
```

Resolvemos el lab:
![image](https://github.com/user-attachments/assets/88aa4b5c-ea21-4a1b-a75a-21d047e412d4)

Inspeccionamos el DOM para ver la inyección:
![image](https://github.com/user-attachments/assets/5631f1f6-6f47-4c32-a214-047de45bbf8e)

Se puede visualizar que la inyección de un nuevo atributo fue exitosa.






