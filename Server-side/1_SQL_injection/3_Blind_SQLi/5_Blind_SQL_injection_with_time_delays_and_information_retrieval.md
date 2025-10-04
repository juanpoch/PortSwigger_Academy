# Lab: Blind SQL injection with time delays and information retrieval

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows or causes an error. However, since the query is executed synchronously, it is possible to trigger conditional time delays to infer information.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.

To solve the lab, log in as the `administrator` user. 

[SQLi cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

---

Parámetro vulnerable: `TrackingId`

Objetivos: 
- Explotar una SQLi time-based para imprimir la contraseña del usuario `administrator`.
- Autenticarse como `administrator`

---

Iniciamos el laboratorio y nos encontramos con un shop online. La petición tramita el parámetro `TrackingId` el cual es vulnerable:

<img width="1502" height="810" alt="image" src="https://github.com/user-attachments/assets/70a07891-acb4-4094-8a56-7d43ec4752a8" />

Nosotros sabemos que la aplicación no devuelve los resultados de la consulta, tampoco hay respuestas diferentes según la consulta arroje filas o no y tampoco causa errores verbosos. Lógicamente, si inyectamos el caracter `'` no notaremos ningún comportamiento diferente:
<img width="1495" height="785" alt="image" src="https://github.com/user-attachments/assets/0fdb1daf-9d92-4c00-892a-eabd86cbfba3" />

---

`Paso 1`: Confirmar que el parámetro es vulnerable

Comenzamos con el payload `' || (pg_sleep(10))--` correspondiente a `PostgreSql`:

<img width="1882" height="837" alt="image" src="https://github.com/user-attachments/assets/66108eae-fd24-4bae-ade8-d4418b138ee8" />

Vemos que la aplicación tardó 10 segundos en contestar, por lo que confirmamos que el parámetro es vulnerable y nos encontramos con un motor `PostgreSql`.


---

`Paso 2`: Confirmar que la tabla `users` existe en la base de datos.

 Utilizamos el payload `' || (select case when (1=1) then pg_sleep(10) else pg_sleep(-1) end)--`:
<img width="1917" height="850" alt="image" src="https://github.com/user-attachments/assets/db24a65c-e724-4d28-a20e-651ddb9832a8" />

Vemos que tardó 10 segundos en responder. Ahora probamos el caso contrario, inyectamos el payload `' || (select case when (1=1) then pg_sleep(10) else pg_sleep(-1) end)--` el cual lógicamente no tarda 10 segundos en responder:
<img width="1913" height="846" alt="image" src="https://github.com/user-attachments/assets/875b22e7-9eee-4373-a76b-ab835a12df8c" />

Confirmamos que existe la tabla `users` inyectando el payload `' || (select case when (1=1) then pg_sleep(10) else pg_sleep(-1) end from users)--` y viendo que tarda 10 segundos en responder:
<img width="1916" height="842" alt="image" src="https://github.com/user-attachments/assets/e30747a4-ecbf-44ad-a325-a8cbaafab142" />
Paralelamente inyectamos la consulta sobre una tabla no existente demostrando que no tarda 10 segundos:
<img width="1917" height="850" alt="image" src="https://github.com/user-attachments/assets/b561ff68-0d9c-42a5-b6bd-e8422c938ed8" />

---

`Paso 3`: Confirmar que existe el usuario `administrator`.


Ahora probamos si existe un usuario `administrator` en la tabla `users` utilizando el payload `' || (select case when (username='administrator') then pg_sleep(10) else pg_sleep(-1) end from users)--`. La aplicación tarda 10 segundos, por lo que confirmamos la existencia del usuario `administrator`:
<img width="1912" height="841" alt="image" src="https://github.com/user-attachments/assets/ca473f70-6750-4100-a4d6-008830172d81" />


---

`Paso 4`: Enumerar la longitud de la contraseña

Utilizamos el payload  `' || (select case when (username='administrator' and LENGTH(password)>1) then pg_sleep(10) else pg_sleep(-1) end from users)--`:
<img width="1915" height="835" alt="image" src="https://github.com/user-attachments/assets/1674f409-a138-457a-9d6e-5f85bc4ac569" />

Como tardó 10 segundos, sabemos que la contraseña tiene una longitud mayor a 1 caracter.

Ahora probamos si la longitud de la contraseña es mayor a 25 caracteres:
<img width="1918" height="840" alt="image" src="https://github.com/user-attachments/assets/f9b49fe1-be0f-4850-b876-ce448699ce18" />

Como no tardó 10 segundos en contestar, ahora sabemos que la contraseña tiene una longitud menor a 25 caracteres.

Mandamos la solicitud al intruder y configuramos el `Sniper Attack` de la siguiente manera:
<img width="1902" height="880" alt="image" src="https://github.com/user-attachments/assets/7b2c5506-f7a5-4b97-b041-5c3cf6d7733f" />

Creamos un nuevo `Resource pool` para no lanzar 10 requests concurrentes:
<img width="611" height="894" alt="image" src="https://github.com/user-attachments/assets/1fb2e358-638d-4cba-ad91-ce8b674349d2" />

Vemos que la aplicación tarda 10 segundos en responder cuando el payload es 19, a partir de 20 la respuesta es inmediata:
<img width="1881" height="892" alt="image" src="https://github.com/user-attachments/assets/a4567aaa-3d10-4ffd-a6f6-fcda8a03092e" />

Por estos datos sabemos que la longitud de la contraseña es de 20 caracteres.

---

`Paso 5`: Enumerar la contraseña del usuario `administrator`

Utilizamos el payload `' || (select case when (username='administrator' and substring(password,1,1)='a') then pg_sleep(10) else pg_sleep(-1) end from users)--`:
<img width="1916" height="863" alt="image" src="https://github.com/user-attachments/assets/2a2c2c9e-3691-438c-a2ee-60251c330da3" />

La respuesta es inmediata, por lo que sabemos que el primer caracter de la contraseña no es `a`.

Enviamos la petición al `Intruder` y realizamos el ataque para el primer caracer:
<img width="1914" height="883" alt="image" src="https://github.com/user-attachments/assets/29ceaf13-281b-4d7a-bc9f-3060abf21f59" />

Vemos que el primer caracter es el `2` porque es la única petición que tardó 10 segundos en responder:
<img width="1878" height="900" alt="image" src="https://github.com/user-attachments/assets/7abfa409-8eac-4e16-bf83-9f7d35b43ff3" />

En vez de hacer 20 ataques manuales para cada posición de la contraseña, realizamos un ataque de `Cluster bomb` con 2 payloads, además ponemos 5 segundos en la función `sleep`:
<img width="1891" height="877" alt="image" src="https://github.com/user-attachments/assets/837731b7-12dc-4ed0-a783-984c956dc927" />

Payload 2:
<img width="1912" height="744" alt="image" src="https://github.com/user-attachments/assets/629960a9-0f1b-47d4-9763-14c8f998ea35" />

Custom resource pool:
<img width="1909" height="902" alt="image" src="https://github.com/user-attachments/assets/167b735c-cdc9-42a1-b3c3-929ec28c9a71" />


Resaltamos las peticiones que tardaron 10 segundos y filtramos en `View Filter` por las que sólo están resaltadas:
<img width="1849" height="524" alt="image" src="https://github.com/user-attachments/assets/357eac3f-1a6f-4e06-87e7-744be12b74cf" />

Contraseña: `2opthktqyjq4s3s6pdzh`

