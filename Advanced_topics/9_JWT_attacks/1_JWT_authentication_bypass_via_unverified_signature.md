# Lab: JWT authentication bypass via unverified signature

This lab uses a JWT-based mechanism for handling sessions. Due to implementation flaws, the server doesn't verify the signature of any JWTs that it receives.

To solve the lab, modify your session token to gain access to the admin panel at `/admin`, then delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

>Tip
>We recommend familiarizing yourself with [how to work with JWTs in Burp Suite](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/jwts) before attempting this lab.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y nos encontramos con un blog público:
![image](https://github.com/user-attachments/assets/03fd7b84-d95f-43bb-aff5-85b4dc9c15b0)

Accedemos al panel de autenticación mediante `My account` y nos autenticamos con nuestras credenciales `wiener:peter` para inspeccionar el mecanismo:
![image](https://github.com/user-attachments/assets/8fcd1ae1-b7b9-4d79-802a-8f538e77ca04)

En esta captura observamos que el servidor nos devuelve el `JWT`:
![image](https://github.com/user-attachments/assets/3d4d4ca2-4bd2-43c0-8f4a-dfcd43c0c9d7)


Luego tramitamos el endpoint `/my-account?id=wiener` con ese `JWT`:
![image](https://github.com/user-attachments/assets/782d0b6e-5867-4f6a-b5c9-fd1988325735)

