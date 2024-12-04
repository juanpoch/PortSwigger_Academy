# Lab: 2FA broken logic

This lab's two-factor authentication is vulnerable due to its flawed logic. To solve the lab, access Carlos's account page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`
You also have access to the email server to receive your 2FA verification code.

Hint: Carlos will not attempt to log in to the website himself.


Describimos el flujo normal de la aplicación utilizando las credenciales:

- Iniciamos sesión con credenciales válidas:
![image](https://github.com/user-attachments/assets/64f381fa-5fc7-48ff-8b00-4ba03740cfda)
 Este endpoint nos brinda una cookie para realizar las siguientes peticiones.

- Con esa cookie solicitamos el recurso que te pide el 2FA:
![image](https://github.com/user-attachments/assets/2c5f499b-9ea8-411d-9864-aeae13b42afa)

Click on `Email client`:
![image](https://github.com/user-attachments/assets/85d1ea4c-91ae-4ae1-995a-8ad474f77157)

Ingresamos el 2FA y recibimos una nueva cookie:
![image](https://github.com/user-attachments/assets/8ea23f39-d282-4c5a-b3a3-62f613921456)

Tramita el siguiente endoint, en el cual ingresamos la nueva cookie e iniciamos sesión:
![image](https://github.com/user-attachments/assets/5533b462-fa84-416e-87bc-f4b6eb7bd634)

- Ahora nos deslogueamos e intentamos replicar el mismo flujo para el usuario carlos, utilizando las credenciales iniciales de wiener:
![image](https://github.com/user-attachments/assets/69e60da7-8796-48af-96d6-1639defb6950)

![image](https://github.com/user-attachments/assets/ef67c05b-d028-4325-b353-2851b5dc1e85)

- El email sigue siendo el de wiener:
![image](https://github.com/user-attachments/assets/4e3f48c5-4129-439f-9aae-4ad9886f4666)

En el Burp Intruder, configuramos el payload para hacer un Sniper Attack al parámetro `mfa-code`. Podríamos filtrar por `302 Found` o por `Incorrect security code` sen `settings`, `Grep - Extract`:


Una vez se realiza el ataque, observamos que logramos iniciar sesión correctamente:






