# Lab: SQL injection UNION attack, retrieving multiple values in a single column

This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.

The database contains a different table called `users`, with columns called `username` and `password`.

To solve the lab, perform a SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the `administrator` user. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

[SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

---

Accedemos al laboratorio y nos encontramos con un shop online:
<img width="1682" height="962" alt="image" src="https://github.com/user-attachments/assets/8826a428-f914-4132-9f1c-15d706e93c95" />

El laboratorio nos dice que posee una vulnerabilidad SQLi en el filtro de categoría de producto. Además sabemos que la aplicación está devolviendo los resultados de la consulta en la respuesta, por lo que podemos utilizar ataques `UNION based`.

Objetivos:

- Determinar el número de columnas en la consulta select, realizando un ataque `UNION`.
- Encontrar una columna que sea compatible con cadenas.
- Realizar un ataque UNION que devuelva todos los usuarios y contraseñas de la tabla `users` y columnas `username` y `password`
- Autenticarnos como el usuario `administrator`


Filtramos por alguna categoría y confirmamos que el parámetro category es vulnerable a SQLi:
<img width="1485" height="765" alt="image" src="https://github.com/user-attachments/assets/1ddb33ca-1f4f-403f-836a-0cf67c7752df" />

Al darnos un `Internal Server Error` confirmamos que es vulnerable a SQLi ya que produjo un error de sintaxis, si comentamos con `'--` resolvemos el error de sintaxis:
<img width="1597" height="820" alt="image" src="https://github.com/user-attachments/assets/7ca0617b-2d86-406b-bf4d-b770a606aec6" />

---

- `Paso 1`: Determinar el número de columnas de la consulta.

Procedemos a determinar el número de columnas que tiene la consulta select usando el payload `' order by 1--`:
<img width="1863" height="810" alt="image" src="https://github.com/user-attachments/assets/e5a9421a-542d-42f2-b760-82ca2652f3b8" />

Devuelve un código de estado 200 por lo que la columna 1 existe. Notamos que los elementos no están siendo ordenados, por lo que la tabla 1 no está siendo mostrada en la pantalla.

Usamos `' order by 2--` obteniendo los mismos resultados:
<img width="1884" height="819" alt="image" src="https://github.com/user-attachments/assets/5cdbd079-4a36-4d7b-92cb-320adf0f1457" />

Usamos `' order by 3--` nos devuelve un `Internal Server Error`, por lo que sabemos que tenemos 2 columnas en la consulta:
<img width="1848" height="618" alt="image" src="https://github.com/user-attachments/assets/460272c9-1de4-4e59-a7b7-f77bb05c2257" />

También podemos probar con el metodo UNION para confirmar usando `' UNION select NULL, NULL--`:

<img width="1873" height="807" alt="image" src="https://github.com/user-attachments/assets/4c48a1ca-b20c-498b-b7c9-e486001386b1" />

---

- `Paso 2`: Determinar qué columna admite cadenas. Probamos con la primer columna usando el payload `' UNION select 'a', NULL--`:
<img width="1873" height="832" alt="image" src="https://github.com/user-attachments/assets/51464e97-13b6-4911-8f4f-a8335f2c58d7" />
Nos arroja `Internal Server Error` por lo que sabemos que la primer columna no admite cadenas.

Probamos con la segunda columna usando el payload `' UNION select NULL, 'a'--`:
<img width="1884" height="836" alt="image" src="https://github.com/user-attachments/assets/cf32e0c9-66a7-4cd6-94a2-a6f68e852558" />

Sabemos entonces que la consulta select tiene 2 columnas, de las cuales sólo la segunda columna admite cadenas.

---

- `Paso 3`: Realizar un ataque UNION que devuelva todos los usuarios y contraseñas de la tabla `users` y columnas `username` y `password`.

Como sólo la segunda consulta admite cadenas, deberemos realizar una concatenación para mostrar los datos de 2 columnas simultáneamente.

Probamos con el operador `||` y un separador cualquiera (`~`) utilizando el payload `' UNION select NULL, username || '~' || password from users--`:
<img width="1871" height="817" alt="image" src="https://github.com/user-attachments/assets/5c7527d9-c457-4462-a8dc-ad479f4ea7f7" />

Obtenemos las credenciales del usuario que necesitamos: `administrator`:`0c5vry42hsflekuwsuea`

---

- `Paso 4`: Autenticarnos como el usuario `administrator`:
<img width="1612" height="641" alt="image" src="https://github.com/user-attachments/assets/f12186aa-b9d4-4d08-8ecd-8b3af072b56b" />
