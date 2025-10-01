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

Esto nos acaba de confirmar que definitivamente realizamos una inyección SQL y que acepta subconsultas.

---

`Paso 2`: Confirmar que la tabla `users` existe en la base de datos.

Inyectamos el payload `' || (select '' from users where rownum = 1) || '`:

<img width="1882" height="812" alt="image" src="https://github.com/user-attachments/assets/84260728-ff62-4c03-aa7a-b486b0097b8e" />

`Nota`: La subconsulta `(select '' from users)` devolvería una fila por cada registro de la tabla users. Si la tabla `users` tiene, por ejemplo, 10 usuarios, esa subconsulta devuelve 10 filas. Pero la consulta externa donde está la inyección solo espera 1 valor (1 fila) para poder concatenarlo en la cadena final, es decir, cuando concatenamos con `||` la query espera un único valor.

En Oracle, `rownum` es una pseudo-columna que numera las filas del resultado a medida que se devuelven. La primera fila devuelta recibe `rownum = 1`.

Por lo tanto la consulta `'abc' || (select '' from users where rownum=1);`  devuelve exactamente una fila y funciona correctamente.

Al obtener el código de estado 200, confirmamos que la tabla users existe.


---

`Paso 3`: Confirmar que el usuario `administrator` existe en la tabla `users`.

En este caso, utilizamos el payload `' || (select '' from users where username='administrator') || '`:


Esto no va a funcionar porque la aplicación no brindará errores tanto si el usuario `administrator` existe como si no existe (la porción del select no se ejecutará).

- Si `administrator` existe → `(select '')` devuelve una fila con `''`.

- Si `administrator` no existe → devuelve 0 filas → la query se convierte en `'valor_original' || NULL || ''` → que es básicamente `'valor_original'`.

<img width="1874" height="793" alt="image" src="https://github.com/user-attachments/assets/b78cb16e-b2ab-4042-98cf-2f6cfe27f51c" />

Usuario no existente:
<img width="1880" height="818" alt="image" src="https://github.com/user-attachments/assets/595cafb9-6906-4a1f-a97b-45e423d66759" />

Procedemos a utilizar el payload `' || (select CASE WHEN (1=0) THEN TO_CHAR(1/0) ELSE '' END FROM dual) || '`:
<img width="1892" height="824" alt="image" src="https://github.com/user-attachments/assets/7ff03595-84d2-4501-b03e-efb278c46015" />

Está bien que arroje un código 200 porque en este caso se ejecutaría la porción que arroja la cadena vacía.

Utilizamos ahora el payload ' || (select CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual) || '
<img width="1883" height="817" alt="image" src="https://github.com/user-attachments/assets/1dc6ed76-9d30-437c-8198-a82c0a6a038b" />

En este caso vemos que al ser (1=1) verdadero, se ejecuta la porción (1/0) generando un error.

---


