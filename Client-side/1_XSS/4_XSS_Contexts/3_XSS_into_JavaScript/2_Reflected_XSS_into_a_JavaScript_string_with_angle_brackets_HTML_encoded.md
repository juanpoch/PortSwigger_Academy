# Lab: Reflected XSS into a JavaScript string with angle brackets HTML encoded

This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality where angle brackets are encoded. The reflection occurs inside a JavaScript string. To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos probando la funcionalidad de búsqueda, insertando una cadena arbitraria que nos permita ver el contexto de reflexión:
![image](https://github.com/user-attachments/assets/99d7695e-effc-4a6a-99d7-6d1aec4bb049)

Vemos que nuevamente el contexto es entre etiquetas `<script>`, dentro de la variable searchTerms y el valor atribuido es una cadena, además sabemos que los caracteres `<>` están siendo codificados.
![image](https://github.com/user-attachments/assets/5ef3d8e1-5adb-4d05-b3a1-581eb4f7f11e)

Por lo tanto vamos a intentar realizar un breaking out of the string:
![image](https://github.com/user-attachments/assets/d9b6c3b2-4beb-4432-ad2f-3e6868f66f6d)

Vimos que así resolvimos el lab:
![image](https://github.com/user-attachments/assets/aaab06e8-72a3-4883-a0a7-8689a4d82796)



