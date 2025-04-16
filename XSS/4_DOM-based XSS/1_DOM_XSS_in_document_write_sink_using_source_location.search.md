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

Analizemos más detalladamente la segunda reflexión:

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

---






