# Lab: Stored XSS into anchor href attribute with double quotes HTML-encoded
This lab contains a stored cross-site scripting vulnerability in the comment functionality. To solve this lab, submit a comment that calls the `alert` function when the comment author name is clicked. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---


Iniciamos el laboratorio y nos encontramos con un Blog público:
![image](https://github.com/user-attachments/assets/e28a5eea-e8bb-4299-af01-d1572b642ee0)

Hacemos click en `View post` para acceder a los post de otros usuarios:
![image](https://github.com/user-attachments/assets/1e2a27c8-c518-4790-a772-b95116afe164)

También podemos comentar el post, además nosotros sabemos que este laboratorio tiene una funcionalidad de comentario vulnerable, por lo que procedemos a insertar un comentario de prueba para ver el comportamiento:
![image](https://github.com/user-attachments/assets/53c7ba6c-153b-4d61-aa81-d55925644073)

Vemos que la `url` se refleja en el atributo `href`, por lo tanto inyectamos el siguiente payload:
```html
javascript:alert(document.domain)
```
![image](https://github.com/user-attachments/assets/59767406-798c-46f4-abac-23aceecb512b)
Resolvemos el lab al hacer clic en nuestro nombre de usuario:
![image](https://github.com/user-attachments/assets/43f9b6c3-09bd-41d2-8aab-ade31570b577)



