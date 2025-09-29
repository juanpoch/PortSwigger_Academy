# Lab: Blind SQL injection with conditional responses

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and no error messages are displayed. But the application includes a `Welcome back` message in the page if the query returns any rows.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.

To solve the lab, log in as the `administrator` user. 

`Hint`: You can assume that the password only contains lowercase, alphanumeric characters. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

[SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)


---

Objetivos:

- Enumerar la contraseña del administrador.
- Autenticarse como `administrator`.

Accedemos al laboratorio y nos encontramos con un shop online:
<img width="1557" height="982" alt="image" src="https://github.com/user-attachments/assets/d2de3b92-37ce-4435-9d9f-09e8f6454707" />

Si filtramos por categoría, vemos que aparece el mensaje de bienvenida `Welcome back!`. Esto es porque una de las cookies de seguimiento disparan este comportamiento:
<img width="1599" height="956" alt="image" src="https://github.com/user-attachments/assets/101e094d-315b-41e1-a924-5deb093583b5" />

Esta cookie es el campo vulnerable del laboratorio llamado `TrackingId`:
<img width="1507" height="798" alt="image" src="https://github.com/user-attachments/assets/0b2bb9bc-ca4d-4c44-b362-5622d11fe406" />

Seguramente se está realizando una query del estilo `select TrackingId from tracking-table where TrackingId = 'eifuyQdkjayog4Go'`

Si este id de seguimiento ya existe en la base de datos porque ya hemos visitado el sitio previamente con este Id, esta consulta devuelve información (en esta consulta devolvería el tracking-id) y la página nos devuelve un mensaje de bienvenida (`Welcome back!`)

---

- `Paso 1`: Confirmar que el parámetro es vulnerable





