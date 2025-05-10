# Lab: DOM XSS in jQuery anchor href attribute sink using location.search source

This lab contains a DOM-based cross-site scripting vulnerability in the submit feedback page. It uses the jQuery library's `$` selector function to find an anchor element, and changes its `href` attribute using data from `location.search`.

To solve this lab, make the "back" link alert `document.cookie`.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---


Iniciamos el laboratorio y nos encontramos con una página para visualizar comentarios:
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

Como notamos que efectivamente el valor del parámetro se está inyectando como valor del atributo `href` sin ningún tipo de valor, procedemos a insertar el siguiente payload: `javascript:alert(document.cookie)` como valor del parámetro `returnPath` y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/f1c26743-1099-4b62-9d41-e5732f04cacf)

`Nota`: Para activar el popup debemos hacer click en el botón `< Back`

---

...

### ❓ ¿Por qué usamos `javascript:alert(document.cookie)` y no solo `alert(...)`?

Cuando insertamos código en el atributo `href` de un enlace (`<a>`), el navegador **espera recibir una URL o URI válida**. No basta con inyectar `alert(1)`, porque eso **no es una URL válida** y el navegador no lo ejecutará como código.

En cambio, el esquema `javascript:` le dice al navegador: *"Ejecutá el código que sigue como JavaScript"*. Por lo tanto:

```html
<a href="javascript:alert(document.cookie)">Back</a>
```

Cuando el usuario haga clic en ese enlace, se ejecutará la función `alert(document.cookie)`.

| Inyección                           | ¿Funciona? | ¿Por qué?                                                                |
| ----------------------------------- | ---------- | ------------------------------------------------------------------------ |
| `alert(1)`                          | ❌          | No es una URL válida, el navegador intenta navegar a una URL inexistente |
| `javascript:alert(1)`               | ✅          | Ejecuta código JavaScript en el contexto de la página                    |
| `javascript:alert(document.cookie)` | ✅          | Ejecuta código para obtener cookies del usuario                          |

Esta técnica es típica en ataques de tipo **DOM-based XSS**, donde el valor de un parámetro de la URL se inyecta como destino de un atributo sensible (`href`, `src`, etc.).

---

## ✅ Conclusiones

- El laboratorio presenta una vulnerabilidad **DOM-based XSS** donde el valor del parámetro `returnPath` es insertado directamente en el atributo `href` de un enlace mediante jQuery, sin ningún tipo de validación ni sanitización.
- Al permitir que el valor `href` sea controlado por el usuario, se habilita el uso de esquemas peligrosos como `javascript:`, lo que puede derivar en la ejecución de código arbitrario cuando se hace clic en el enlace.
- La reflexión no ocurre en el código fuente servido por el servidor, sino que se produce únicamente en el DOM a través de código JavaScript.

---

## 🛡️ Recomendaciones

- **Nunca insertar directamente esquemas peligrosos como `javascript:` en atributos sensibles como `href`, `src`, o `action`.**
- Validar explícitamente que los valores inyectados en `href` comiencen con protocolos seguros como `https://` o rutas relativas `/ruta`.
- Utilizar funciones que codifiquen o filtren entradas, especialmente cuando se trabaja con librerías como jQuery que manipulan directamente el DOM.
- Considerar una política de **Content Security Policy (CSP)** para bloquear la ejecución de URIs tipo `javascript:`.

---

## 🎓 Lecciones aprendidas

- La función `.attr("href", ...)` en jQuery puede ser peligrosa si se le pasa directamente contenido controlado por el usuario, ya que el navegador interpreta ese contenido como un destino legítimo.
- Los ataques basados en `javascript:` como `javascript:alert(document.cookie)` siguen siendo efectivos si no hay validación del esquema del URI.
- Este tipo de XSS ocurre exclusivamente en el DOM (no en la respuesta HTML), lo que demuestra la importancia de revisar también el JavaScript del lado cliente al auditar una aplicación.
