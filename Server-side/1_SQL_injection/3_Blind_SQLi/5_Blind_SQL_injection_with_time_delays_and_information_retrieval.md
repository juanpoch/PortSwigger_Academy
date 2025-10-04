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
