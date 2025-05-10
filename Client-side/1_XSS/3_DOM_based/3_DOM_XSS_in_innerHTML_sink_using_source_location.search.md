# Lab: DOM XSS in innerHTML sink using source location.search

This lab contains a DOM-based cross-site scripting vulnerability in the search blog functionality. It uses an `innerHTML` assignment, which changes the HTML contents of a `div` element, using data from `location.search`.

To solve this lab, perform a cross-site scripting attack that calls the `alert` function.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Notas de Portswigger:
El receptor `innerHTML` no acepta elementos `script` en ningún navegador moderno, ni activa eventos `svg`, `onload`. Esto significa que deberá usar elementos alternativos como `img` o `iframe`. Los controladores de eventos como `onload` y `onerror` pueden usarse junto con estos elementos. Por ejemplo:

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

Luego tenemos el siguiente fragmento de código, el cual es utilizado para insertar dinámicamente el valor que se refleja en la segunda etiqueta `<span>`:
```html
<script>
    function doSearchQuery(query) {
        document.getElementById('searchMessage').innerHTML = query;
    }
    var query = (new URLSearchParams(window.location.search)).get('search');
    if(query) {
        doSearchQuery(query);
    }
</script>
```

## 🧠 Análisis del script

```js
function doSearchQuery(query) {
    document.getElementById('searchMessage').innerHTML = query;
}
```

🔹 Se define una función llamada `doSearchQuery` que **toma un parámetro `query`** y lo **inserta en el DOM** dentro del elemento con `id="searchMessage"`.

❗️ **Peligro**: Usa `.innerHTML`, lo cual **interpreta el contenido como HTML**, no como texto plano. Esto habilita **inyección de código HTML o JavaScript** si no se filtra el input del usuario.

---

```js
var query = (new URLSearchParams(window.location.search)).get('search');
```

🔹 Extrae el valor del parámetro `search` de la URL (todo lo que esté después de `?`).

---

```js
if(query) {
    doSearchQuery(query);
}
```

🔹 Si existe el parámetro `search`, llama a la función `doSearchQuery()` y le pasa el valor del usuario.

---


## 🔥 Resumen

Este código tiene una vulnerabilidad de tipo **DOM-based XSS**, ya que:

- Usa `.innerHTML` (interpreta HTML).
- Toma un valor **directamente de la URL**.
- Lo inyecta sin validación ni escape.

---

Como vimos, el valor que insertamos en el parámetro `search` se refleja en la etiqueta `<span>` dinamicamente con JavaScript:
![image](https://github.com/user-attachments/assets/f6dfaf22-c231-438d-8b7a-dcc34edcf091)

Lo que queda ahora es intentar inyectar etiquetas `<script>` pero no están siendo ejecutadas:
![image](https://github.com/user-attachments/assets/6f961993-6d86-46bf-9df6-ddf95bf258d7)

Como anunciamos al inicio del lab, las etiquetas `<script>` no serán ejecutadas en estos casos, por lo que podemos utilizar el siguiente payload:
- `<img src=0 onerror=alert(1)>`

![image](https://github.com/user-attachments/assets/9d0d0aa9-f468-4b6f-85b3-ac3b83c97b62)
![image](https://github.com/user-attachments/assets/a704227f-a5dd-4710-b4a4-48f9be049687)


