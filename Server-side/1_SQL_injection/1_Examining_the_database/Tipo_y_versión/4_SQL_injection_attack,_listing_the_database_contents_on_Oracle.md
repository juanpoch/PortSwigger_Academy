# Lab: SQL injection attack, listing the database contents on Oracle

This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.

The application has a login function, and the database contains a table that holds usernames and passwords. You need to determine the name of this table and the columns it contains, then retrieve the contents of the table to obtain the username and password of all users.

To solve the lab, log in as the `administrator` user. 

`Hint`: On Oracle databases, every `SELECT` statement must specify a table to select `FROM`. If your `UNION SELECT` attack does not query from a table, you will still need to include the `FROM` keyword followed by a valid table name.

There is a built-in table on Oracle called `dual` which you can use for this purpose. For example: `UNION SELECT 'abc' FROM dual`

[SQLi Cheet Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)  

---

Objetivos:

- Determinar qué tabla contiene los usuarios y las contraseñas.
- Determinar losnombres de columnas en la tabla.
- Imprimir el contenido de la tabla.
- Loguearse como administrator.


Accedemos al laboratorio y nos encontramos con la aplicación de shopping. Sabemos que el filtro de categoría de producto es vulnerable, por lo que procedemos a chequearlo inyectando el caracter `'`:
<img width="1509" height="805" alt="image" src="https://github.com/user-attachments/assets/86d45147-8a67-4204-900e-1d91885b8129" />

Al darnos un `Internal Server Error` confirmamos que es vulnerable a SQLi ya que produjo un error de sintaxis.

- Determinar el número de columnas que utiliza la consulta vulnerable (tenemos título del elemento y descripción del mismo por lo que al menos tenemos 2 columnas): Probamos con `' order by 2--` y nos arroja un código de estado 200:
<img width="1880" height="789" alt="image" src="https://github.com/user-attachments/assets/d524e242-53f5-471f-a75f-3346557a9316" />

Probamos con ' order by 3-- y nos arroja 500 Internal Server Error:
<img width="1882" height="797" alt="image" src="https://github.com/user-attachments/assets/74c602e2-104f-4a6b-8029-296fd6dc7cd4" />

Podemos confirmar que tenemos 2 columnas con nuestro metodo `UNION select null, null from dual--` ya que estamos ante ORACLE:
<img width="1872" height="791" alt="image" src="https://github.com/user-attachments/assets/3453b0d8-3aac-4b13-9b62-5269811730d2" />


- Ahora procedemos a analizar el tipo de dato que tienen las columnas, probamos con cadenas:
<img width="1868" height="791" alt="image" src="https://github.com/user-attachments/assets/73b939bc-f0e1-43dc-8081-53fbc010d88c" />

Por lo que sabemos que las columnas aceptan cadenas como tipo de dato.

- Averiguamos la versión, confirmamos que es ORACLE, usamos el payload `UNION select banner, 'a' FROM v$version--` y filtramos por oracle:
<img width="1875" height="808" alt="image" src="https://github.com/user-attachments/assets/17ce4807-8aa3-4b53-b9f7-6833a2d0692c" />

Nos brinda la versión `Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production`.
