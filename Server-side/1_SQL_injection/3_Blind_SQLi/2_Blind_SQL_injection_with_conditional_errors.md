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

- Imprimir la contraseña del usuario `administrator`.
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

Ahora probamos hacer la misma consulta con el siguiente payload `' || (select '' from noexiste) || '` esperando obtener un `Internal Server Error`:

<img width="1885" height="852" alt="image" src="https://github.com/user-attachments/assets/e9e7d9fd-e89f-4cce-93db-1c483d1afec0" />

Esto nos acaba de confirmar que definitivamente realizamos una inyección SQL.

---

`Paso 2`: Confirmar que la tabla `users` existe en la base de datos.

Inyectamos el payload `' || (select '' from users where rownum = 1) || '`:

<img width="1882" height="812" alt="image" src="https://github.com/user-attachments/assets/84260728-ff62-4c03-aa7a-b486b0097b8e" />

Al obtener el código de estado 200, confirmamos que la tabla users existe. Tuvimos que agregar

`Nota`: lLa subconsulta `(select '' from users)` devolvería una fila por cada registro de la tabla users. Si la tabla `users` tiene, por ejemplo, 10 usuarios, esa subconsulta devuelve 10 filas. Pero la consulta externa donde está la inyección solo espera 1 valor (1 fila) para poder concatenarlo en la cadena final.

En Oracle, `rownum` es un pseudo-columna que numera las filas del resultado a medida que se devuelven. La primera fila devuelta recibe `rownum = 1`.

