# Lab: Password reset broken logic

This lab's password reset functionality is vulnerable. To solve the lab, reset Carlos's password then log in and access his "My account" page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)

---

Iniciamos el lab y tenemos el típico blog:
![image](https://github.com/user-attachments/assets/04daf798-c568-47e3-8702-f748bdc19dda)

Ingresamos al panel de login a través del botón `My account`:
![image](https://github.com/user-attachments/assets/c8654c04-fe13-4f94-af3a-672b769182c6)

Capturando el tráfico con `Burp Suite`, inspeccionamos el flujo de la funcionalidad `Forgot password?`:
![image](https://github.com/user-attachments/assets/a3bfe564-6773-4847-aa76-747cc08d1d47)

Ingresamos nuestro usuario `wiener` para inspeccionar la siguiente request:
![image](https://github.com/user-attachments/assets/128465ab-393e-4dcb-86cd-b546c755214b)

Como nos pide que ingresemos a nuestro email, inspeccionamos el mail utilizando el botón `Email client`, vemos que nos brinda un link de reseteo de contraseña:
![image](https://github.com/user-attachments/assets/d23ddbba-b28a-4b15-a473-20fdc0c5cd5f)

Este es un link único y temporal generado automáticamente para el usuario gracias a la generación del token aleatorio, que se inserta en el link, como el valor del parámetro `temp-forgot-password-token`. Accedemos al link de reseteo de contraseña:
![image](https://github.com/user-attachments/assets/cac8c6af-3f41-47e4-bacc-1c2c9af17354)

El link contiene un parámetro `temp-forgot-password-token`.
Ese token es el que autoriza el restablecimiento de la contraseña.

Ingresamos la nueva contraseña dos veces y realizamos el cambio de contraseña para nuestro usuario:
![image](https://github.com/user-attachments/assets/695b8b3b-58ad-4fad-b8b6-9c881fa30ff6)

Podemos ver que el servidor podría estar validando que el parámetro `temp-forgot-password-token` sea el mismo tanto en la url como en el cuerpo de la solicitud, en vez de validar que el token pertenezca al usuario cuya contraseña se quiere cambiar. Si esto es cierto, podríamos intentar utilizar esta petición para cambiar la contraseña del usuario víctima `carlos`.

Procedemos a intentar cambiar la contraseña de `carlos` utilizando el `Repeater`:
![image](https://github.com/user-attachments/assets/f0184fb6-2d67-4d13-bd7b-8dc06c18fbae)

Vemos que pudimos cambiar la contraseña con éxito!

Iniciamos sesión como `carlos` y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/d6f5d7b9-df94-4d55-a3fd-aed84e590f62)


### Conclusión

- El servidor NO estaba validando correctamente que el token perteneciera al usuario cuya contraseña se quería cambiar.

- Aceptaba cualquier username en el cuerpo de la solicitud, mientras el token simplemente existiera.

- Resultado: Password reset broken logic → reseteo de contraseñas cruzadas.

Podríamos reintentar el cambio de contraseña modificando el valor del parámetro `temp-forgot-password-token`, pero procurando que sea el mismo tanto en la url como en el cuerpo de la solicitud:
![image](https://github.com/user-attachments/assets/40509117-a1d7-45b2-bd8d-cf9b53469e04)

Confirmando nuestra teoría.

🔎 Notas adicionales:

- Riesgo real en producción: Este tipo de fallos permitiría que atacantes reinicien contraseñas de usuarios críticos (admin, soporte, usuarios VIP).

- Mitigación correcta: Asociar internamente cada token a un único usuario en la base de datos y validar esa asociación durante todo el flujo.









