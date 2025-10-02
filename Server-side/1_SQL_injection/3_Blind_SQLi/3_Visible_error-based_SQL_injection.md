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

Ahora procedemos a realizar la misma inyección pero le añadimos el comentario:
<img width="1864" height="795" alt="image" src="https://github.com/user-attachments/assets/c7d3fa2e-1cec-4283-887a-a4a566cdd3c0" />

Vemos que la salida de la inyección no está siendo reflejada en la página, por lo que tenemos un escenario de inyeción ciega.

---


Utilizamos la función `CAST` con el payload `' AND CAST((SELECT 1) as int)--`:

<img width="1884" height="667" alt="image" src="https://github.com/user-attachments/assets/679df05b-5595-4d1c-b983-84bb4dfb7033" />

El servidor nos responde que el argumento luego del `AND` debería ser booleano y no entero, por eso se produce el error.

Por lo que inyectamos el payload `' AND 1=CAST((SELECT 1) as int)--` y vemos que solucionamos el error:
<img width="1890" height="831" alt="image" src="https://github.com/user-attachments/assets/ea42bc12-61c2-41ff-b44f-3df9050fe2a7" />


Ahora inyectamos el payload `' AND 1=CAST((SELECT 'abc') as int)--`:
<img width="1880" height="633" alt="image" src="https://github.com/user-attachments/assets/983f928f-bffd-4e36-80cb-e3d9695da9af" />

Vemos que el servidor devuelve el string literal como sospechabamos. Este comportamiento podría permitir imprimir información que no conozcamos dentro de una consulta `SELECT`.


Inyectamos el payload `' AND 1=CAST((SELECT username from users) as int)--`:
<img width="1890" height="804" alt="image" src="https://github.com/user-attachments/assets/e764268f-81fc-42c4-955f-45e6c5463744" />


Vemos el error `Undeterminated string literal` y además vemos que la salida de nuestra consulta `CAST` está truncada, por lo que la respuesta nos está sugiriendo que hay algún tipo de límite a la cantidad de caracteres.


