# Lab: Reflected XSS into HTML context with nothing encoded

This lab contains a simple reflected cross-site scripting vulnerability in the search functionality.

To solve the lab, perform a cross-site scripting attack that calls the `alert` function. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

# XSS Vulnerability Demonstration



Al iniciar el laboratorio nos encontramos con un blog público:
![image](https://github.com/user-attachments/assets/97ebaf7e-2e01-4df1-b0c4-e039cae7ff5a)

Sabemos que el laboratorio presenta una funcionalidad de búsqueda vulnerable. Realizamos una búsqueda con el término `test` para analizar su comportamiento:
![image](https://github.com/user-attachments/assets/61a21000-a4f5-4084-ac8f-d3432188ae7c)

Notamos que se tramita el parámetro `search=test`, y que su valor se refleja directamente dentro de una etiqueta `<h1>`, sin codificación ni escape.

Para comprobar si el contenido es inyectable, intentamos insertar una etiqueta HTML:
![image](https://github.com/user-attachments/assets/a058951c-6850-420f-9963-08afaac768bd)

El navegador interpreta correctamente la etiqueta HTML, lo que indica que el contexto es **HTML plano**, sin filtros ni codificación. Esto nos permite insertar etiquetas `<script>` directamente.

Inyectamos el siguiente payload clásico de prueba:
```javascript
<script>alert(1)</script>
```
El script es ejecutado con éxito y resolvemos el laboratorio:

![image](https://github.com/user-attachments/assets/91fcbce6-a29f-41e3-8fee-f3ec6212b020)

---

---

## ✅ Conclusiones

- El laboratorio presenta una vulnerabilidad **reflected XSS** donde el parámetro `search` se refleja sin codificar dentro del HTML.
- El navegador interpreta la entrada del usuario como parte del DOM, permitiendo la ejecución de scripts arbitrarios.
- No existe ninguna medida de mitigación como escaping, sanitización o cabeceras de seguridad.

---

## 🛡️ Recomendaciones

- Escapar correctamente cualquier entrada del usuario antes de insertarla en el HTML (**HTML entity encoding**).
- Utilizar funciones seguras de salida como `textContent` (en JavaScript) o `htmlspecialchars()` (en PHP).
- Implementar cabeceras HTTP como `Content-Security-Policy` y `X-Content-Type-Options`.
- Evitar reflejar directamente parámetros de la URL sin validación o escape.

---

## 🎓 Lecciones aprendidas

- Los ataques de **reflected XSS** pueden ejecutarse cuando la entrada del usuario es devuelta en la respuesta sin ninguna validación o codificación.
- Inyectar código en un contexto HTML plano (por ejemplo, dentro de un `<h1>`) es una señal clara de una posible vulnerabilidad.
- El payload `<script>alert(1)</script>` sigue siendo una herramienta eficaz para probar ejecuciones básicas de JavaScript en el navegador.



