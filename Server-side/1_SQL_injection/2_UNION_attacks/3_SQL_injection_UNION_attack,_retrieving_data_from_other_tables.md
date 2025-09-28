# Lab: SQL injection UNION attack, retrieving data from other tables

This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you need to combine some of the techniques you learned in previous labs.

The database contains a different table called `users`, with columns called `username` and `password`.

To solve the lab, perform a SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the `administrator` user. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

[SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

---

Accedemos al laboratorio y nos encontramos con un shop online:
<img width="1545" height="981" alt="image" src="https://github.com/user-attachments/assets/8f0174fc-e358-4254-bad2-1b886714f8d2" />

El laboratorio nos dice que posee una vulnerabilidad SQLi en el filtro de categoría de producto.
Además sabemos que la aplicación está devolviendo los resultados de la consulta en la respuesta, por lo que podemos utilizar ataques `UNION based`.

Objetivos:

- Determinar el número de columnas en la consulta select, realizando un ataque `UNION`.
- Encontrar una columna que sea compatible con cadenas.
- Realizar un ataque `UNION` que devuelva todos los usuarios y contraseñas de la tabla `users` y columnas `username` y `password`
- Autenticarnos como el usuario `administrator`


Filtramos por alguna categoría y confirmamos que el parámetro category es vulnerable a SQLi:
<img width="1493" height="829" alt="image" src="https://github.com/user-attachments/assets/4583141e-99e6-47a9-bc7b-8a6733563b47" />

Al darnos un `Internal Server Error` confirmamos que es vulnerable a SQLi ya que produjo un error de sintaxis, si comentamos con `'--` resolvemos el error de sintaxis:
<img width="1517" height="818" alt="image" src="https://github.com/user-attachments/assets/7057bf37-b395-4771-a314-7db82cfc6d36" />

Procedemos a determinar el número de columnas que tiene la consulta select usando el payload `' order by 1--`:
<img width="1873" height="803" alt="image" src="https://github.com/user-attachments/assets/37e8ac1a-86d8-4a23-b052-780e3b037bb7" />
La aplicación está devolviendo el resultado de la consulta en la respuesta. Además ordena el resultado por la columna especificada.

Usamos `' order by 2--` obteniendo los mismos resultados:
<img width="1860" height="785" alt="image" src="https://github.com/user-attachments/assets/8d54d222-7e09-4232-8d15-ff179b4877de" />

Usamos `' order by 3--` nos devuelve un `Internal Server Error`, por lo que sabemos que tenemos 2 columnas en la consulta:
<img width="1873" height="673" alt="image" src="https://github.com/user-attachments/assets/f2fa67dc-eb87-4371-b38c-6e785224e018" />

También podemos probar con el metodo UNION para confirmar usando `' UNION select NULL, NULL--`:
<img width="1868" height="807" alt="image" src="https://github.com/user-attachments/assets/6372cd13-0b06-4e6b-837f-d10ef86e8f87" />

---

- Paso 2, determinar qué columna admite cadenas.
Probamos con la primer columna usando el payload `' UNION select 'a', NULL--`:
<img width="1875" height="845" alt="image" src="https://github.com/user-attachments/assets/622e8229-25db-4c78-90e4-62bcc6033648" />

Probamos con la segunda columna usando el payload `' UNION select 'a', 'a'--`:
<img width="1864" height="854" alt="image" src="https://github.com/user-attachments/assets/4040f4e3-b66b-45a3-8d79-58d41ec0b46d" />


Sabemos que tenemos 2 columnas y ambas admiten cadena como tipo de dato.

---

- Realizar un ataque `UNION` que devuelva todos los usuarios y contraseñas de la tabla `users` y columnas `username` y `password`

Procedemos a realizar la consulta con el payload `' UNION select username, password FROM users--`:
<img width="1858" height="822" alt="image" src="https://github.com/user-attachments/assets/6204d256-1806-4a03-8f90-b8650b56d747" />
