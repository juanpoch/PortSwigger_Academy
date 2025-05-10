# Lab: DOM XSS in `document.write` sink using source `location.search`

This lab contains a DOM-based cross-site scripting vulnerability in the search query tracking functionality. It uses the JavaScript `document.write` function, which writes data out to the page. The `document.write` function is called with data from `location.search`, which you can control using the website URL.

To solve this lab, perform a cross-site scripting attack that calls the `alert` function.  


![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 


---

Iniciamos el laboratorio y nos encontramos con un blog público, el cual tiene la funcionalidad de búsqueada a través de una query string:
![image](https://github.com/user-attachments/assets/d812c1dd-b38d-4bf4-990f-307ee98adb58)


Realizamos una búsqueda de prueba para localizar dónde está siendo reflejada, utilizamos nuestro payload `abc123xy`:
![image](https://github.com/user-attachments/assets/e6e406cd-027a-43de-8274-065ee1f087b6)


Pero si inspeccionamos el DOM, vemos la reflexión en 2 lugares distintos:
![image](https://github.com/user-attachments/assets/872486a6-a0a9-4b92-abd4-4fe40440dbfb)

- Dentro de la etiqueta `<h1>`: Como vimos en Burp Suite, es parte de la respuesta que está enviando el servidor.
- Dentro de la etiqueta `<img>`: Esto está siendo reflejado en el DOM.

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


El condicional es el encargado de llamar a la función `trackSearch(query);` si se pasa un parámetro para `query`.  

---

Debido a que la reflexión se dá dentro de la etiqueta `img`, dentro del atributo `src`, procedemos a realizar un break out y salirnos del atributo, cerrándolo y añadiendo un nuevo atributo.

Ingresamos el siguiente payload:

```js
abc123xy" onload="alert(1)
```

Recordar que nosotros tenemos esta etiqueta:
```html
<img src="/resources/images/tracker.gif?searchTerms=abc123xy">
```

Una vez inyectado el payload, la etiqueta quedaría así:
```html
<img src="/resources/images/tracker.gif?searchTerms=abc123xy" onload="alert(1)">
```
✅ Con esta técnica logramos cerrar el atributo `src` con `"`, e inyectamos un nuevo atributo: `onload="alert(1)"`.

Esto provoca que cuando el navegador renderiza la imagen, se ejecute `alert(1)` como parte del evento `onload`.

Este tipo de ataque se conoce como **attribute injection** mediante *break out*, y es común cuando la inyección ocurre dentro de un atributo HTML. Permite ejecutar código sin necesidad de etiquetas `<script>`.  

Resolvemos el lab:
![image](https://github.com/user-attachments/assets/88aa4b5c-ea21-4a1b-a75a-21d047e412d4)

Inspeccionamos el DOM para ver la inyección:
![image](https://github.com/user-attachments/assets/5631f1f6-6f47-4c32-a214-047de45bbf8e)

Se puede visualizar que la inyección de un nuevo atributo fue exitosa.


---

## ✅ Conclusiones

- El laboratorio presenta una vulnerabilidad **DOM-based XSS** causada por el uso inseguro de `document.write` en combinación con una fuente controlada por el usuario: `location.search`.
- El parámetro `search` es insertado sin sanitización dentro del atributo `src` de una etiqueta `<img>`, lo que permite realizar un ataque al manipular el DOM en tiempo real.
- La reflexión no ocurre en el código fuente del servidor, sino **en el DOM generado dinámicamente por JavaScript en el navegador**.

---

## 🛡️ Recomendaciones

- **Evitar el uso de `document.write()`**, especialmente cuando se manejan datos del usuario. Usar métodos más seguros como `createElement()` y `textContent`.
- Validar y sanitizar cualquier entrada proveniente de `location`, `document`, `cookie`, etc., antes de usarla en el DOM.
- Aplicar políticas de **Content Security Policy (CSP)** para limitar la ejecución de scripts inyectados.
- Utilizar frameworks modernos que manejan automáticamente la sanitización del DOM, como React o Angular.

---

## 🎓 Lecciones aprendidas

- Las vulnerabilidades **DOM XSS** no son visibles en el código fuente del servidor, sino que se generan por cómo el navegador procesa el DOM.
- Identificar el "sink" (`document.write`, `innerHTML`, etc.) y la fuente (`location.search`) es clave para analizar este tipo de ataques.
- En este caso, al reflejarse dentro de un atributo HTML (`src`), fue necesario hacer un **break out** del atributo y usar un evento (`onload`) para ejecutar código.
- El payload `abc123xy" onload="alert(1)` demuestra que incluso atributos aparentemente seguros pueden ser explotados si no hay validación.
