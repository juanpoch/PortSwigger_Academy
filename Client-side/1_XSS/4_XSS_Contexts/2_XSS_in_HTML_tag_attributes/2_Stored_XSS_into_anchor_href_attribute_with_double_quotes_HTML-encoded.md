# Lab: Stored XSS into anchor href attribute with double quotes HTML-encoded
This lab contains a stored cross-site scripting vulnerability in the comment functionality. To solve this lab, submit a comment that calls the `alert` function when the comment author name is clicked. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---


Iniciamos el laboratorio y nos encontramos con un Blog público:
![image](https://github.com/user-attachments/assets/e28a5eea-e8bb-4299-af01-d1572b642ee0)

Hacemos click en `View post` para acceder a los post de otros usuarios:
![image](https://github.com/user-attachments/assets/1e2a27c8-c518-4790-a772-b95116afe164)

También podemos comentar el post, además nosotros sabemos que este laboratorio tiene una funcionalidad de comentario vulnerable, por lo que procedemos a insertar un comentario de prueba para ver el comportamiento:
![image](https://github.com/user-attachments/assets/947fdb12-538e-43ab-be65-4d4bca2ed560)

![image](https://github.com/user-attachments/assets/53c7ba6c-153b-4d61-aa81-d55925644073)

Vemos que la `url` se refleja en el atributo `href`, por lo tanto estamos ante una posible implementación del caso 3, "Atributos que permiten ejecución directa (href, src, etc.)".

Inyectamos el siguiente payload:
```html
javascript:alert(document.domain)
```
En este caso, el valor inyectado se refleja directamente dentro del atributo href sin codificar los dos puntos (:) ni bloquear el protocolo javascript, lo que permite ejecutar código al hacer clic:
![image](https://github.com/user-attachments/assets/59767406-798c-46f4-abac-23aceecb512b)
Resolvemos el lab al hacer clic en nuestro nombre de usuario:
![image](https://github.com/user-attachments/assets/43f9b6c3-09bd-41d2-8aab-ade31570b577)

Al ser un Stored XSS, el payload queda persistido en el sistema y se ejecuta cada vez que alguien visualiza el comentario y hace clic en el autor.

---

---

## ✅ Conclusiones

- Este laboratorio presenta una vulnerabilidad de **Stored XSS** que ocurre en el atributo `href` de un enlace (`<a>`), donde el valor introducido por el usuario no es validado ni filtrado adecuadamente.
- Al reflejar directamente el valor proporcionado dentro del atributo, se permite el uso del esquema `javascript:`, lo que habilita la ejecución de código arbitrario cuando un usuario hace clic.
- La vulnerabilidad se encuentra en la funcionalidad de comentarios y queda almacenada de forma persistente en el sistema, afectando a cualquier usuario que interactúe con el enlace inyectado.

---

## 🛡️ Recomendaciones

- Restringir los valores permitidos en atributos `href` a esquemas seguros como `https://` y `mailto:`, bloqueando explícitamente `javascript:` y similares.
- Escapar adecuadamente los valores inyectados en atributos HTML (por ejemplo, codificando `"`, `'`, `:` y espacios).
- Validar y sanear las entradas del usuario antes de persistirlas y reflejarlas.
- Implementar una política de **Content Security Policy (CSP)** que impida la ejecución de scripts inyectados.
- Usar funciones de salida seguras para generar atributos dinámicamente (como `setAttribute()` en lugar de `innerHTML`).

---

## 🎓 Lecciones aprendidas

- El esquema `javascript:` en un atributo `href` puede ser suficiente para ejecutar XSS al hacer clic en el enlace, sin necesidad de cerrar la etiqueta o inyectar `<script>`.
- Las vulnerabilidades de tipo **Stored XSS** pueden tener mayor impacto que las Reflected, ya que afectan a todos los usuarios que interactúan con el contenido persistido.
- Entender el **contexto de inyección** es clave: en atributos como `href`, `src` o `action`, ciertos valores pueden implicar ejecución directa.
- Incluso si las comillas dobles están codificadas, un atributo mal controlado puede seguir siendo explotable si el valor aceptado no está validado correctamente.




