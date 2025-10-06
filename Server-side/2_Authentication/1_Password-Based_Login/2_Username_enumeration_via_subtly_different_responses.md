# Lab: Username enumeration via subtly different responses
This lab is subtly vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

- [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)  

---

Iniciamos el laboratorio y nos encontramos con un blog:
<img width="1882" height="804" alt="image" src="https://github.com/user-attachments/assets/7866a86c-fd21-4e66-a30d-41a5276bcda3" />

Nos dirijimos a probar el panel de autenticación en `My account`:

<img width="1868" height="767" alt="image" src="https://github.com/user-attachments/assets/0ef0744a-e87b-4f7c-b127-0cc64d165fe1" />

Enviamos credenciales de prueba para analizar la petición:
<img width="1875" height="781" alt="image" src="https://github.com/user-attachments/assets/b72512db-2d88-4a0f-bebe-5cdbc5f4c516" />

Enviamos la solicitud al `Intruder` y realizamos un `Sniper attack` testeando el campo `username` con la wordlist proporcionada:
<img width="1867" height="863" alt="image" src="https://github.com/user-attachments/assets/3069c2af-c127-43b8-9482-64fcd52b9a4b" />

Realizamos el ataque y buscamos por diferencias en el código de estado o en el Length:

<img width="1839" height="639" alt="image" src="https://github.com/user-attachments/assets/9b318673-6273-456e-94a0-b40c0787d152" />

Vemos que las longitudes son muy similares y tampoco hay diferencias en los códigos de estado.
