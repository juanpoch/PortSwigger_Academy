# Lab: DOM XSS in jQuery anchor href attribute sink using location.search source

This lab contains a DOM-based cross-site scripting vulnerability in the submit feedback page. It uses the jQuery library's `$` selector function to find an anchor element, and changes its `href` attribute using data from `location.search`.

To solve this lab, make the "back" link alert `document.cookie`.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Tenemos una página para visualizar comentarios:
![image](https://github.com/user-attachments/assets/c51ee4ab-fecc-4c7e-a839-55ebac682c97)


Si entramos a `submit feedback`:
![image](https://github.com/user-attachments/assets/98eafaa0-6259-411e-bed4-9b368e31ef88)

Tenemos la función de dejar un comentario.

Inspeccionamos la funcionalidad de `< Back`:
![image](https://github.com/user-attachments/assets/5e0b44b4-75ba-484a-9fe8-6079610571d1)


Vemos la reflexión en el siguiente fragmento de código:
```html
<div class="is-linkback">
    <a id="backLink" href="/">Back</a>
</div>
```
Esto simplemente genera un enlace `<a>` con el texto "Back" y el atributo `id="backLink"`, dentro de un `div`.

Luego tenemos el `<script>` de abajo, que genera un `href` para el enlace:
```html
<script>
    $(function() {
        $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
    });
</script>
```

Este script usa `jQuery` para ejecutar una función cuando la página termina de cargar. Dentro de esa función, selecciona un enlace HTML con el ID `backLink` y le asigna dinámicamente un atributo `href` utilizando el valor del parámetro `returnPath` extraído de la URL actual. Esto significa que si la URL del navegador contiene `?returnPath=valor`, ese valor se insertará como destino del enlace. Si no se valida correctamente, un atacante podría manipular ese parámetro (por ejemplo, usando `javascript:alert(1)`) para ejecutar código malicioso cuando el usuario haga clic en el enlace, lo que representa una vulnerabilidad de tipo `DOM-based XSS`.

Para validarlo, inyectamos un valor arbitrario de prueba al parámetro `returnPath=abc123xy`:
![image](https://github.com/user-attachments/assets/e10e9abf-c4e7-45dd-9518-ce249356bd82)

Como notamos que efectivamente el valor del parámetro se está inyectando como valor del atributo `href` sin ningún tipo de valor, procedemos a insertar el siguiente payload: `javascript:alert(document.cookie)` como valor del parámetro `returnPath` y hacemos click en `back`:
![image](https://github.com/user-attachments/assets/5e70f43c-ceef-4861-bb78-9d855d818f11)


---
