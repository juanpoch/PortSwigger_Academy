# Lab: Authentication bypass via OAuth implicit flow

This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the client application makes it possible for an attacker to log in to other users' accounts without knowing their password.

To solve the lab, log in to Carlos's account. His email address is `carlos@carlos-montoya.net`.

You can log in with your own social media account using the following credentials: `wiener:peter`.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y nos encontramos con un blog público:
![image](https://github.com/user-attachments/assets/6ab96322-ed8d-4a44-8eab-8666d9cb392f)

Accedemos al panel de autenticación mediante el botón `My account`, el servidor nos redirige al panel de autenticación mediante social media:
![image](https://github.com/user-attachments/assets/ac9cd0fb-3837-483c-ae39-0ba66ad2c5b1)

Nos autenticamos con nuestras credenciales `wiener:peter`:
![image](https://github.com/user-attachments/assets/ddf98926-9cf4-4f9d-880a-d211bb28d0d9)

La aplicación nos solicita autorizar su acceso a nuestro perfil y email, por lo que aceptamos haciendo clic en `Continue`:
![image](https://github.com/user-attachments/assets/bc042af2-5e13-418c-a910-8bd35f8b4b2e)

Vemos que se tramita una solicitud POST al endpoint `/authenticate` con los siguientes datos:
```json
{"email":"wiener@hotdog.com","username":"wiener","token":"S-E6OGelo7ngSiSaKGJcaRLDfIKiwSXv38rgYWQ_QIn"}
```

- Se está enviando un `access_token` directamente en el cuerpo `JSON` junto con `username` y `email`.

- Esto es típico de un flujo `OAuth Implicit` o una mala implementación del `Authorization Code Flow`, donde el cliente almacena el token en el navegador y luego lo reutiliza para autenticarse.

El servidor nos responde con la siguiente cookie de sesión: `2Iwx9sYwwm7NmI7IOXZ6TRzusBZhcy8c`, lo que indica que nos autenticamos correctamente.


Si no existe ningún tipo de validación entre el token y los datos, y a su vez se permite la reutilización del token, podremos usar la dirección de email del usuario carlos (`carlos@carlos-montoya.net`) e intentar autenticarnos como tal:
![image](https://github.com/user-attachments/assets/1fdf1321-9ce4-40f2-a948-24230995a202)

Para resolver el laboratorio, debemos abrir el dashboard del usuario `carlos` con las cookies proporcionadas por el servidor. Para eso una forma de hacerlo es con clic derecho on la request and seleccionar `"Request in browser" > "In original session"`. Copiar esta URL y visitarla en el navegador:
![image](https://github.com/user-attachments/assets/4ba7e744-3219-45bd-b625-3c170d123ddd)

---


  


