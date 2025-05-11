# Lab: Reflected XSS into attribute with angle brackets HTML-encoded
This lab contains a reflected cross-site scripting vulnerability in the search blog functionality where angle brackets are HTML-encoded. To solve this lab, perform a cross-site scripting attack that injects an attribute and calls the `alert` function. 

`Hint:` Just because you're able to trigger the `alert()` yourself doesn't mean that this will work on the victim. You may need to try injecting your proof-of-concept payload with a variety of different attributes before you find one that successfully executes in the victim's browser. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y nos encontramos con un blog público:
![image](https://github.com/user-attachments/assets/c75eae1f-42fb-4424-850d-e7544faa8b04)


Sabemos que este laboratorio tiene una vulnerabilidad en la funcionalidad de búsqueda del blog, por lo que ingresamos un payload de prueba y vemos que es reflejado en 2 oportunidades, una de ellas es en contexto de atributo:
![image](https://github.com/user-attachments/assets/04515733-0eeb-45f0-9c3e-e9f7e0744fd0)

Vemos que escapa los signos `<>`:
![image](https://github.com/user-attachments/assets/0b81427a-892c-4d60-af6d-3a6b673c5ca3)

Intentamos inyectar el siguiente payload:
```html
" autofocus onfocus=alert(document.domain) x="
```
![image](https://github.com/user-attachments/assets/f6eb7620-cf36-4d7e-a319-0d57c474a4a0)

Vemos que resolvimos el lab:
![image](https://github.com/user-attachments/assets/b1ec7c96-4460-4624-80d9-9c3ccd4ae03d)

Explicación:
- `autofocus`: Hace que el campo de input reciba el foco automáticamente.
- `onfocus=alert(document.domain)`: Define un handler de evento, que se ejecuta cuando el input recibe el foco.
- `x="`: 	Agrega un atributo inventado `(x)` con una comilla de cierre, para evitar romper el HTML

