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

Realizamos una petición con credenciales de prueba para analizar el comportamiento:
<img width="1886" height="789" alt="image" src="https://github.com/user-attachments/assets/0fd4a561-e1ac-4363-a7be-c371ab009ef2" />
