# Lab: DOM XSS in innerHTML sink using source location.search

This lab contains a DOM-based cross-site scripting vulnerability in the search blog functionality. It uses an `innerHTML` assignment, which changes the HTML contents of a `div` element, using data from `location.search`.

To solve this lab, perform a cross-site scripting attack that calls the `alert` function.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)

---

Notas de Portswigger:
El receptor `innerHTML` no acepta elementos `script` en ningún navegador moderno, ni activa eventos `svg` `onload`. Esto significa que deberá usar elementos alternativos como `img` o `iframe`. Los controladores de eventos como `onload` y `onerror` pueden usarse junto con estos elementos. Por ejemplo:

`element.innerHTML='... <img src=1 onerror=alert(document.domain)> ...'`

---


En este lab tenemos una funcionalidad de búsqueda y tal como venimos haciendo, vamos a realizar una búsqueda de prueba para analizar las reflexiones:
![image](https://github.com/user-attachments/assets/aaf3f55d-ae89-403b-864f-a129bd98c754)


Vemos que la reflexión se dá dentro de la etiqueta `<span>` en el elemento `h1`:
```html
<h1><span>0 search results for '</span><span id="searchMessage"></span><span>'</span></h1>
```

En este fragmento de código tenemos un encabezado `<h1>` que contiene 3 etiquetas `<span>`:
- La primera muestra la cadena literal `0 search results for '`
- La segunda inserta un valor dinámicamente con JavaScript (aquí se produce nuestra reflexión).
- La última cierra la estructura con la comilla simple `'`.


