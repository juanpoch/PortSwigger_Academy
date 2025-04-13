# Lab: Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped

This lab contains a reflected cross-site scripting vulnerability in the search blog functionality. The reflection occurs inside a template string with angle brackets, single, and double quotes HTML encoded, and backticks escaped. To solve this lab, perform a cross-site scripting attack that calls the `alert` function inside the template string.

---

El sitio web es un blog que permite realizar búsquedas, procedemos a realizar una búsqueda de prueba para analizar el contexto de la reflexión:

![image](https://github.com/user-attachments/assets/126d5c60-3856-44a9-8e8f-0e2f7f108d12)

Vemos dos reflexiones, una entre etiquetas `<h1>` y la otra entre etiquetas `<script>`

La segunda es interesante porque la reflexión se encuentra entre `template literal`.

🧠 Template literals

Son una forma de escribir strings multilinea o interpolados en JavaScript, usando backticks (```) en lugar de comillas `'` o `"`. Permiten insertar variables o expresiones directamente dentro del string, con la sintaxis `${...}`.


