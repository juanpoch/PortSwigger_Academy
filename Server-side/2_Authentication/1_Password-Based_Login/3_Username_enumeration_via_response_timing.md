# Lab: Username enumeration via response timing

This lab is vulnerable to username enumeration using its response times. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

- `Your credentials`: `wiener`:`peter`
- [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

`Hint`: To add to the challenge, the lab also implements a form of IP-based brute-force protection. However, this can be easily bypassed by manipulating HTTP request headers. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)  

---

Iniciamos el laboratorio y nos encontramos con un blog:

<img width="1874" height="751" alt="image" src="https://github.com/user-attachments/assets/ed9d7095-9bed-4e4f-a819-0074acfd27ad" />

Nos dirijimos a `My account` para inspeccionar el panel de login:
<img width="1887" height="810" alt="image" src="https://github.com/user-attachments/assets/cfb9e4fa-a4a4-42e3-bf08-2c15c04e2b0d" />

Realizamos una petición con credenciales de prueba para analizar el comportamiento cuando el usuario es inválido:
<img width="1916" height="874" alt="image" src="https://github.com/user-attachments/assets/418af68c-d51d-46b6-bace-b3e1a10e2239" />

Vemos que la respuesta tarda 235 millis en llegar.

Ahora probamos con un usuario válido:

<img width="1915" height="870" alt="image" src="https://github.com/user-attachments/assets/5e540710-2058-499d-8ef3-877399c1ffb6" />

Tenemos un tiempo de 252 millis, lo que no es una diferencia significativa.

Vemos que si probamos 3 veces nos bloquean:
<img width="1908" height="852" alt="image" src="https://github.com/user-attachments/assets/8724bf35-2886-408f-87e5-bfb5a6537c2d" />

Procedemos a utilizar el header `X-Forwarded-For`:

<img width="833" height="253" alt="image" src="https://github.com/user-attachments/assets/601885e6-c8b2-4c36-8ad0-fc7be14e8516" />

<img width="1882" height="713" alt="image" src="https://github.com/user-attachments/assets/2a1805db-0620-4912-ad6f-4766ec88d100" />
