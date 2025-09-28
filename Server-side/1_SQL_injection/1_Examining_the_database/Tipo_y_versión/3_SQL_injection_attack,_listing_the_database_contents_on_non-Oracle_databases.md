# Lab: SQL injection attack, listing the database contents on non-Oracle databases

This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.

The application has a login function, and the database contains a table that holds usernames and passwords. You need to determine the name of this table and the columns it contains, then retrieve the contents of the table to obtain the username and password of all users.

To solve the lab, log in as the `administrator` user. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

[SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

---

En este laboratorio debemos realizar los siguientes objetivos:
- Determinar la tabla que contiene usuarios y contraseñas.
- Determinar las columnas relevantes.
- Imprimir el contenido de la tabla.
- Loguearse como administrador.

Iniciamos el laboratorio y nos encontramos con un shop online:
<img width="1368" height="945" alt="image" src="https://github.com/user-attachments/assets/2de87a5d-6cdd-400c-831c-3c0b2a8cdd36" />

Sabemos que tenemos el parámetro `category` vulnerable a `SQLi`. Procedemos a confirmarlo, inyectándole `'`:
<img width="1878" height="806" alt="image" src="https://github.com/user-attachments/assets/6f6c112f-af5b-49b5-985c-99dd81e8bcc7" />

Al darnos un `Internal Server Error` confirmamos que es vulnerable a SQLi ya que produjo un error de sintaxis.

- Determinar el número de columnas que utiliza la consulta vulnerable (tenemos título del elemento y descripción del mismo por lo que al menos tenemos 2 columnas):
Probamos con `' order by 2--` y nos arroja un código de estado 200:
<img width="1881" height="763" alt="image" src="https://github.com/user-attachments/assets/851873eb-3588-4dd8-a148-dd67435d4b7e" />

Probamos con `' order by 3--` y nos arroja 500 Internal Server Error:
<img width="1873" height="777" alt="image" src="https://github.com/user-attachments/assets/f92cd391-9e95-42b1-a363-81ee3812df73" />

Podemos confirmar que tenemos 2 columnas con nuestro metodo `UNION`:
<img width="1872" height="684" alt="image" src="https://github.com/user-attachments/assets/89a7d059-4b12-4748-9cd6-e3bb72a9a7cc" />

