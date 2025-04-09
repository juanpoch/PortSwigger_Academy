Lab: Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped

This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality where angle brackets and double are HTML encoded and single quotes are escaped.

To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

---

El contexto de la reflexión es el mismo caso que el ejercicio 2, realizamos una inyección de prueba para identificarlo:
![image](https://github.com/user-attachments/assets/b021da45-b77c-4a3f-b5f4-c8b3accc111d)

Vemos que la comilla simple `'` está siendo escapada:
![image](https://github.com/user-attachments/assets/004ad9a5-7499-41d2-a7a1-c10bda8cd341)

Pero no así la barra invertida `\`:
![image](https://github.com/user-attachments/assets/20d8ab18-0ad8-44d1-9ea2-6a35280b6001)

Por lo que podemos escaparla con nuestra propia barra invertida:
![image](https://github.com/user-attachments/assets/cd54b63b-3646-482c-a3c9-091207bb3385)

Vemos que con este payload pudimos resolver el lab:
![image](https://github.com/user-attachments/assets/289232a1-455e-4555-8d00-6bfecee90108)





