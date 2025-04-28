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

Observamos que obtenemos el mísmo `Lenght` 3248 para todas las respuestas:
![image](https://github.com/user-attachments/assets/5ccd4de0-9c61-43cf-8162-df33752bb4cf)

Cuando finaliza el ataque, observamos que para el usuario `af` tenemos una `Lenght` diferente y al observar la respuesta también notamos que es diferente:
![image](https://github.com/user-attachments/assets/8178deaa-fd03-4257-b582-54d8109ed83a)

Recibimos la cadena `Incorrect password` en la respuesta, por lo que podemos proceder a utilizar este usuario para realizar fuerza bruta de contraseñas utilizando la wordlist proporcionada por el laboratorio:











