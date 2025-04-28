# Lab: Username enumeration via different responses

This lab is vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

- [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)  

---

Ingresamos al laboratorio y tenemos un típico website blog:
![image](https://github.com/user-attachments/assets/4ceeef43-68e8-4430-9d70-2090a6d79f89)

Ingresamos al panel de login haciendo click en `My account`:
![image](https://github.com/user-attachments/assets/573b4575-1624-4e6e-872b-560c5c05e009)

Intentamos iniciar sesión con credenciales de prueba:
![image](https://github.com/user-attachments/assets/64dec745-99d6-4611-b8b2-6e897f490688)

La respuesta ya nos da un indicio de que podría haber un potencial vector de enumeración de usuarios.

Al haber capturado la request con Burp Suite, envíamos la misma al repeater para realizar fuerza bruta utilizando la wordlist proporcionada por el laboratorio, realizamos un `Sniper Attack`.

Observamos que obtenemos el mísmo `Length` 3248 para todas las respuestas:
![image](https://github.com/user-attachments/assets/5ccd4de0-9c61-43cf-8162-df33752bb4cf)

Cuando finaliza el ataque, observamos que para el usuario `af` tenemos una `Length` diferente y al observar la respuesta también notamos que es diferente:
![image](https://github.com/user-attachments/assets/8178deaa-fd03-4257-b582-54d8109ed83a)

Recibimos la cadena `Incorrect password` en la respuesta, por lo que podemos proceder a utilizar este usuario para realizar fuerza bruta de contraseñas utilizando la wordlist proporcionada por el laboratorio:
![image](https://github.com/user-attachments/assets/75f784cc-f419-425b-b239-4fbb35d54845)


Finaliza el ataque y vemos que cuando el usuario y la contraseña son válidos nos redirige con un código de estado 302 a `/my-account?id=af`:
![image](https://github.com/user-attachments/assets/b7ec6da5-f0e5-4fbb-bba5-b46e90fc66fb)

Utilizamos el usuario `af` y contraseña `111111` obtenidos para iniciar sesión y resolver el laboratorio:
![image](https://github.com/user-attachments/assets/13de0d97-626f-41ca-8274-107434d30d8a)















