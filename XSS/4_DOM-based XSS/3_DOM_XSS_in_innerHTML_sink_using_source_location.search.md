# Lab: DOM XSS in innerHTML sink using source location.search

This lab contains a DOM-based cross-site scripting vulnerability in the search blog functionality. It uses an `innerHTML` assignment, which changes the HTML contents of a `div` element, using data from `location.search`.

To solve this lab, perform a cross-site scripting attack that calls the `alert` function.

---

Notas de Portswigger:
El receptor `innerHTML` no acepta elementos `script` en ningún navegador moderno, ni activa eventos `svg` `onload`. Esto significa que deberá usar elementos alternativos como `img` o `iframe`. Los controladores de eventos como `onload` y `onerror` pueden usarse junto con estos elementos. Por ejemplo:

`element.innerHTML='... <img src=1 onerror=alert(document.domain)> ...'`

---

