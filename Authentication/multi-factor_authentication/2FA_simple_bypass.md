# Lab: 2FA simple bypass

This lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, access Carlos's account page.

- Your credentials: wiener:peter
- Victim's credentials carlos:montoya


Iniciamos sesión con las credenciales de Carlos y vemos que nos piden un 2FA:
![image](https://github.com/user-attachments/assets/0e1ee201-4512-4f60-8c8b-26616ace93bb)

Cuando vemos el historial del burp, podemos ver que el 2FA lo tramita después de haber tramitado el login:
![image](https://github.com/user-attachments/assets/a681a079-25bf-4112-bc79-989d14d037a1)

Además vemos que el servidor nos devuelve un `302 Found` con la cookie de sesión, lo que nos da un indicio de que el 2FA lo tramita después de haber iniciado sesión correctamente:
![image](https://github.com/user-attachments/assets/ff1215bb-1bd2-42f2-b128-4a40528b9434)

