# Lab: Blind SQL injection with conditional errors

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows. If the SQL query causes an error, then the application returns a custom error message.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.

To solve the lab, log in as the `administrator` user. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

[SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

---

En este laboratorio tenemos un parámetro vulnerable llamado `TrackingId`. Este parámetro es vulnerable a blind SQLi.

La aplicación realiza una consulta SQL con el valor del parámetro `TrackingId`, pero la misma no retorna ningún resultado visible y tampoco es posible diferenciar resultados diferentes basados en si la consulta devuelve una fila o no. 

Objetivos:

- Imprimir la contraseña del usuario `administrator`-
- Autenticarse como administrador.

---

Accedemos al laboratorio y nos encontramos con un shop online:
<img width="1621" height="875" alt="image" src="https://github.com/user-attachments/assets/f768cfdb-8906-433c-a91e-82f03bb4b284" />

Si examinamos la petición en BurpSuite vemos en la misma el parámetro `TrackingId`:
<img width="1886" height="829" alt="image" src="https://github.com/user-attachments/assets/a0256c23-0134-48f2-bef3-40a7ea69c0dd" />

Procedemos a intentar romper la consulta inyectando el caracter `'`:
<img width="1517" height="823" alt="image" src="https://github.com/user-attachments/assets/4d51b732-6c4c-48b4-9402-8c026a671cd7" />

Obtenemos un `Internal Server Error`, por lo que sabemos que pudimos romper la cadena de consulta.

Ahora inyectamos `'--` para sanear la consulta:
<img width="1879" height="812" alt="image" src="https://github.com/user-attachments/assets/a0659d1b-797e-4009-a699-280ee0b91717" />

Con estos pasos demostramos que la aplicación es vulnerable a SQLi.

Procedemos a inyectar `' || (select '') || '`, que es una sintáxis válida para SQL:

<img width="1865" height="790" alt="image" src="https://github.com/user-attachments/assets/e4e403d8-b98b-4a41-8262-352af3b8060e" />

Seguramente no acepta esta sintáxis porque ORACLE necesita la cláusula FROM. 

Procedemos a confirmarlo realizando la inyección del payload `' || (select '' from dual) || '`:

<img width="1878" height="810" alt="image" src="https://github.com/user-attachments/assets/313e0358-89a1-4f1c-ab1d-8140f9a6669b" />

Confirmamos que nos encontramos ante ORACLE.





