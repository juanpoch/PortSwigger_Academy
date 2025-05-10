# Lab: Reflected XSS into HTML context with nothing encoded

This lab contains a simple reflected cross-site scripting vulnerability in the search functionality.

To solve the lab, perform a cross-site scripting attack that calls the `alert` function. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

# XSS Vulnerability Demonstration



Iniciamos el laboratorio y nos encontramos con un blog:
![image](https://github.com/user-attachments/assets/97ebaf7e-2e01-4df1-b0c4-e039cae7ff5a)

Nosotros tenemos que encontrar algún input que controlemos y que pueda verse reflejado. Sabemos que este laboratorio tiene una funcionalidad de búsqueda vulnerable, por lo que buscamos la palabta `test` para analizar su comportamiento:
![image](https://github.com/user-attachments/assets/61a21000-a4f5-4084-ac8f-d3432188ae7c)

Vemos que se está tramitando el parámetro `search=test`, el cual está siendo reflejado en una cadena dentro de etiquetas `<h1></h1>`.

Cuando inyectamos etiquetas `HTML`, observamos que son inyectadas en eñ source código y ejecutadas: 
![image](https://github.com/user-attachments/assets/a058951c-6850-420f-9963-08afaac768bd)

Nosotros sabemos que entre etiquetas `<h1>` podemos intentar inyectar etiquetas `<script></script>`, por lo que intentamos inyectar el siguiente payload:
```javascript
<script>alert(1)</script>
```
Inyectamos el payload y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/91fcbce6-a29f-41e3-8fee-f3ec6212b020)

---




