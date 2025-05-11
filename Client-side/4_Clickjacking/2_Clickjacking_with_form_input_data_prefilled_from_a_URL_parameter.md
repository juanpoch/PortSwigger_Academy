# Lab: Clickjacking with form input data prefilled from a URL parameter

This lab extends the basic clickjacking example in `Lab: Basic clickjacking with CSRF token protection`. The goal of the lab is to change the email address of the user by prepopulating a form using a URL parameter and enticing the user to inadvertently click on an "Update email" button.

To solve the lab, craft some HTML that frames the account page and fools the user into updating their email address by clicking on a "Click me" decoy. The lab is solved when the email address is changed.

You can log in to your own account using the following credentials: `wiener:peter`

`Hint`: You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y nos encontramos con un blog público:
![image](https://github.com/user-attachments/assets/fda2376e-c775-4d09-a76d-f9441833f9c0)

Objetivo del laboratorio:

Hacer que el usuario víctima, al hacer clic en un señuelo que dice "Click me", actualice su dirección de email por una controlada por el atacante, aprovechando que el formulario:

- Se puede prellenar con parámetros en la URL.

- Puede ser activado visualmente mediante clickjacking.

Procedemos a autenticarnos con nuestras credenciales `wiener:peter`, en el dashboard del usuario vemos que tenemos la funcionalidad de `Update email`:
![image](https://github.com/user-attachments/assets/68c2680e-3eed-4e72-ae2c-9781dd823585)

El siguiente paso es verificar que al ingresar una dirección de correo y presionar “Update email”, se envía un formulario prellenado, posiblemente con un CSRF token.

Cambiamos el mail por `test@test.com`:
![image](https://github.com/user-attachments/assets/4d0619fa-f003-4c81-9740-d70531fb93b6)

Observamos el código fuente y vemos lo siguiente:
![image](https://github.com/user-attachments/assets/6cd03705-1106-442e-9479-bd0372375e87)

Lo primero que podemos observar de esto es lo siguiente:

- Envía una petición POST al endpoint `/my-account/change-email` con 2 parámetros (`email` y `csrf="CVx76vmrM8PTmiqRpDDdESV1Z9GkHBQI"` )

Procedemos a validar si existe la precarga del formulario usando parámetros en la URL
Entonces, de ser cierto, el campo `email` en el formulario:
```html
<input required type="email" name="email" value="">
```
...puede ser prellenado vía parámetro GET. 
Esto indica que si accedemos a:
```perl
https://YOUR-LAB-ID.web-security-academy.net/my-account?email=hacker@attacker.com
```
...el valor se carga en el input del formulario sin intervención del usuario. Esto es clave para el ataque de clickjacking.

Hacemos la prueba y validamos que efectivamente existe la precarga del formulario usando parámetros en la URL:
![image](https://github.com/user-attachments/assets/7827582b-0a77-4b77-9053-9dc5948c1496)

Esto se puede combinar con un ataque de clickjacking para presentar un formulario listo para enviar, sobre el cual el usuario haga clic sin saberlo.



