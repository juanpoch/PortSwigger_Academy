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

- Si este id de seguimiento ya existe en la base de datos porque ya hemos visitado el sitio previamente con este Id, esta consulta devuelve información (en esta consulta devolvería el tracking-id) y la página nos devuelve un mensaje de bienvenida (`Welcome back!`).
- Si el tracking id no existe, la query no devuelve nada, y no vemos ningún mensaje de bienvenida.

Lo probamos, añadiendo un caracter al parámetro `TrackingId`:
<img width="1508" height="814" alt="image" src="https://github.com/user-attachments/assets/3de64f98-0472-496b-80e6-ec3e43e0bf47" />


---

- `Paso 1`: Confirmar que el parámetro es vulnerable

Comprobamos que inyectando el caracter `'` se rompe la sintaxis, porque utilizando el mismo TrackingId no nos devuelve el mensaje de bienvenida:
<img width="1519" height="860" alt="image" src="https://github.com/user-attachments/assets/228f6ad5-ad2c-41e3-89df-7529a92de46d" />

Pero nos encontramos ante un caso de blind SQLi porque la consulta no nos devuelve ninguna información.

Utilizamos las condiciones booleanas para demostrar la diferencia de comportamiento de la aplicación cuando la condición es verdadera y falsa.

- Utilizando el payload `' AND '1'='1`:
`select TrackingId from tracking-table where TrackingId = 'eifuyQdkjayog4Go' AND '1'='1'`
- - Utilizando el payload `' AND 1=1--`:
`select TrackingId from tracking-table where TrackingId = 'eifuyQdkjayog4Go' AND 1=1--'`

Utilizamos la condición verdadera con el payload `' AND '1'='1` y confirmamos que aparece el mensaje de bienvenida:
<img width="1871" height="801" alt="image" src="https://github.com/user-attachments/assets/d7a9c8d9-3c20-49f4-997e-d77a8bbab315" />
Utilizamos la condición falsa con el payload `' AND '1'='2` y confirmamos que no aparece el mensaje de bienvenida:
<img width="1886" height="828" alt="image" src="https://github.com/user-attachments/assets/b68fa791-ab3e-414b-a61b-a0b7b75a29be" />


Entonces la aplicación cambia de comportamiento según si la condición inyectada es verdadera o falsa:
```
Cookie: TrackingId=xyz' AND '1'='1   --> devuelve "Welcome back"
Cookie: TrackingId=xyz' AND '1'='2   --> no devuelve "Welcome back"
```

---
`Paso 2`: Determinar que existe la tabla users.

Utilizamos una inyección con el payload `' and (select 'x' from users LIMIT 1)='x'--`

Esto le indica que si existe una tabla `users`, genere un valor 'x' para cada entrada en la tabla y se limite a 1 entrada. Si esa entrada que se genera es igual a 'x' entonces la sentencia es verdadera, por lo tanto si la tabla `users` no existe, la condición será falsa.

Recibimos el mensaje `Welcome back!` por lo que confirmamos que la tabla `users` existe:
<img width="1878" height="840" alt="image" src="https://github.com/user-attachments/assets/d2bbe588-96f6-41f4-9f36-996b56f9c82a" />

---

`Paso 3`: Confirmar que el usuario `administrator` existe en la tabla `users`

Utilizamos una inyección con el payload `' and (select username from users where username= 'administrator')='administrator'--`

Recibimos el mensaje `Welcome back!` por lo que confirmamos que existe un usuario `administrator`:
<img width="1868" height="766" alt="image" src="https://github.com/user-attachments/assets/5459f239-a41a-4ba9-845f-cc070a1abaae" />


---
- `Paso 2`: determinar la longitud de la contraseña del usuario administrator:

Utilizamos la inyección con el payload `' AND (SELECT LENGTH(password) FROM users WHERE username='administrator') > 10 --`:
<img width="1872" height="824" alt="image" src="https://github.com/user-attachments/assets/d479aead-ea0b-45ca-9d65-3a91f9a3aad4" />

Nos devuelve el mensaje de bienvenida por lo que la condición es verdadera y podemos confirmar que la contraseña tiene más de 10 caracteres.

Utilizamos la inyección con el payload `' AND (SELECT LENGTH(password) FROM users WHERE username='administrator') > 20 --`:
<img width="1882" height="824" alt="image" src="https://github.com/user-attachments/assets/4014badb-8881-4404-b6f1-f15aa66d6d96" />

La aplicación no nos devuelve el mensaje de bienvenida, por lo tanto sabemos que la contraseña tiene más de 10 caracteres pero no más de 20.

Probamos si la contraseña tiene exactamente 20 caracteres con el payload `' AND (SELECT LENGTH(password) FROM users WHERE username='administrator') = 20 --`
<img width="1886" height="801" alt="image" src="https://github.com/user-attachments/assets/408c3bb8-79cd-45ac-90ec-d924bdc180e9" />

La aplicación nos devuelve el mensaje de bienvenida `Welcome back!`. Confirmamos que la contraseña del usuario administrator posee 20 caracteres.

---

- `Paso 3`:

