# Lab: Reflected XSS into a JavaScript string with angle brackets HTML encoded

This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality where angle brackets are encoded. The reflection occurs inside a JavaScript string. To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y nos encontramos con un foro público:

![image](https://github.com/user-attachments/assets/dc108d1e-fee1-4ce8-b41d-426f5c2834b5)

Iniciamos probando la funcionalidad de búsqueda, insertando una cadena arbitraria que nos permita ver el contexto de reflexión:
![image](https://github.com/user-attachments/assets/99d7695e-effc-4a6a-99d7-6d1aec4bb049)

Vemos que nuevamente el contexto es entre etiquetas `<script>`, dentro de la variable `searchTerms` y el valor atribuido es una cadena, además sabemos que los caracteres `<>` están siendo codificados.
![image](https://github.com/user-attachments/assets/5ef3d8e1-5adb-4d05-b3a1-581eb4f7f11e)

En este contexto, el valor se inserta entre comillas simples dentro de un string JavaScript, por lo que nuestro objetivo es cerrar la cadena, agregar el `alert()`, y luego comentar el resto del script si es necesario.
Por lo tanto vamos a intentar realizar un breaking out of the string utilizando el payload `';alert(document.domain)//`:
![image](https://github.com/user-attachments/assets/d9b6c3b2-4beb-4432-ad2f-3e6868f66f6d)

Vimos que así resolvimos el lab:
![image](https://github.com/user-attachments/assets/aaab06e8-72a3-4883-a0a7-8689a4d82796)


---

---

## ✅ Conclusiones

- Este laboratorio presenta una vulnerabilidad de **Reflected XSS** en un contexto de **cadena dentro de JavaScript**, lo que requiere escapar adecuadamente de la string para ejecutar código.
- Los signos `<` y `>` están codificados, lo que impide la inserción de etiquetas HTML, pero no afecta la ejecución dentro del script.
- Se utilizó un payload que cierra la comilla, introduce un `alert()` y comenta el resto de la línea para evitar errores de sintaxis.

---

## 🛡️ Recomendaciones

- Escapar adecuadamente los valores de usuario antes de insertarlos dentro de cadenas JavaScript (por ejemplo, reemplazar `'`, `"`, `\\`, `\n`, etc.).
- Evitar reflejar directamente datos controlados dentro de bloques `<script>` o strings JavaScript.
- Usar funciones seguras de serialización como `JSON.stringify()` para insertar datos en scripts.
- Implementar Content Security Policy (CSP) para mitigar ejecución de scripts inyectados.

---

## 🎓 Lecciones aprendidas

- En contextos de JavaScript string, el vector principal consiste en **cerrar la cadena** y luego ejecutar código arbitrario.
- A veces no es necesario usar `<script>`, sino simplemente alterar la lógica del script reflejando una instrucción válida.
- El uso de `//` permite anular el código restante si el script continúa en la misma línea.
- Identificar correctamente el delimitador de la cadena (`'` o `"`) es esencial para construir el payload correcto.

