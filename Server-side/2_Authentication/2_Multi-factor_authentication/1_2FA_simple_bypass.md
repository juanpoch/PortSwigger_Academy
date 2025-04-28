# Lab: 2FA simple bypass

This lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, access Carlos's account page.

- Your credentials: `wiener:peter`
- Victim's credentials `carlos:montoya`
  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)  

---

Ingresamos al lab y vemos que es un blog:
![image](https://github.com/user-attachments/assets/289d4b41-9519-4bfc-9664-bac057f3d1c6)

Vamos al panel de login haciendo click en `My account`:
![image](https://github.com/user-attachments/assets/28ffe45b-c7b8-4227-b79a-3572d9ab4808)

Vamos a analizar el proceso de login con nuestras credenciales `wiener:peter`, para inspeccionar utilizamos `Burp Suite`:
![image](https://github.com/user-attachments/assets/596fbaa7-2f55-41b0-9c00-701977cb35d2)

- Se realiza una petición POST al endpoint `/login` enviando usuario `wiener` y contraseña `peter`.

- El servidor responde con un HTTP `302 Found`, que redirecciona al usuario a `/login2`.

- Se establece una nueva cookie de sesión en la respuesta.

Esto indica que el primer paso de autenticación (primer factor) fue exitoso, pero el usuario todavía debe completar un segundo paso en `/login2`.

El login no está totalmente finalizado aún.

Luego analizamos la seguiente petición:
![image](https://github.com/user-attachments/assets/b7486ee7-420d-4b30-ab15-ee4710556ae7)

La solicitud a `/login2` ya lleva una cookie de sesión establecida en el primer paso (`POST /login`).
Es decir, el usuario ya pasó correctamente la validación de usuario y contraseña y ahora está entrando al segundo paso.

En este paso pide un segundo factor, un código, que podémos ver que se envió a nuestro email.

Hacemos click en `Email client`:
![image](https://github.com/user-attachments/assets/3d33eced-b936-440c-a753-acdae641d1ea)

Si observamos la request vemos el código:
![image](https://github.com/user-attachments/assets/3bd8f6fd-b268-422a-8ca8-c53bb3a4b4e4)

Ingresamos el código:
![image](https://github.com/user-attachments/assets/936be345-18ac-4a4f-b366-9e238cb4d290)

Vemos que tenemos una ves más un `302 Found` que nos redirije a `/my-account?id=wiener`:
![image](https://github.com/user-attachments/assets/7f28f470-fe43-4454-ac37-d3031946b754)

Logramos ingresar a la cuenta de `wiener`:
![image](https://github.com/user-attachments/assets/74cdfa92-815f-448d-b97a-fda6d0026d2e)

---

Repetimos el proceso de login con las credenciales del usuario víctima `carlos:montoya`:
![image](https://github.com/user-attachments/assets/172d4948-65f5-40b7-a70e-1fe13f2fd05c)

Vemos que nos arroja una nueva cookie de sesión una vez pasado este primer factor de autenticación exitosamente. Ahora vendría el momento de ingresar el segundo factor de autenticación utilizando esta nueva cookie. Podríamos intentar hacer fuerza bruta de 2FA ya que conocemos que el código contiene 4 caracteres, pero lo que vamos a intentar acceder a áreas de usuarios registrados, con el fin de comprobar que tenemos acceso directo a recursos debido a una mala implementación del 2FA.

Intentamos acceder al recurso `/my-account?id=carlos` utilizando la nueva cookie brindada por el servidor y resolvemos el laboratorio:

![image](https://github.com/user-attachments/assets/83dfb799-0229-471e-b9b5-35205663ba4f)












