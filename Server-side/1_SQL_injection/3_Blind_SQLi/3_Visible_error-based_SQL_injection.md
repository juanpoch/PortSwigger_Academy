# Lab: Visible error-based SQL injection

This lab contains a SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie. The results of the SQL query are not returned.

The database contains a different table called `users`, with columns called `username` and `password`. To solve the lab, find a way to leak the password for the `administrator` user, then log in to their account. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

[SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)


---

Objetivos:

Explotar una SQLi para devolver las credenciales del usuario `administrator` de la tabla `users` y autenticarse en su cuenta.

---

Iniciamos el laboratorio y nos encontramos con un shop online:
<img width="1498" height="781" alt="image" src="https://github.com/user-attachments/assets/5b7dbcd8-4ad9-4928-aecd-51c3f21e499e" />

Podemos ver la cookie customizada llamada `TrackingId` que el laboratorio nos dice que es vulberable.

La consulta que hace el backend por detrás podría ser del estilo:
```sql
select trackingId from table where trackingId='5JR9zWEzi2idX6mH'
```

Procedemos a inyectar el caracter `'` para ver si podemos romper la sintaxis:
<img width="1838" height="576" alt="image" src="https://github.com/user-attachments/assets/b7377160-9e61-46c8-b911-8ec30ba28848" />

Aquí obtenemos la consulta original en el backend gracias a un manejo de errores verboso:
```sql
SELECT * FROM tracking WHERE id = '5JR9zWEzi2idX6mH'
```

Además sabemos que el backend está esperando una cadena y por eso se produjo el error.


