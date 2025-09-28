# Lab: SQL injection attack, querying the database type and version on Oracle

This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.

To solve the lab, display the database version string.

`Hint`: On Oracle databases, every `SELECT` statement must specify a table to select `FROM`. If your `UNION SELECT` attack does not query from a table, you will still need to include the `FROM` keyword followed by a valid table name.

There is a built-in table on Oracle called `dual` which you can use for this purpose. For example: `UNION SELECT 'abc' FROM dual `

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

[SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

---


Iniciamos el laboratorio y nos encontramos con un shop online:
<img width="1571" height="964" alt="image" src="https://github.com/user-attachments/assets/4240dc43-a451-414c-8f8a-2bfd4610ad71" />

El laboratorio nos pide que mostremos la cadena de versión de la base de datos, puntualmente habla de `ORACLE`.

El laboratorio nos dice que contiene una vulnerabilidad de `SQLi` en el filtro de categoría de producto y que podemos realizar un ataque `UNION`.

Accedemos a la categoría `Lifestyle` e intentamos realizar una inyección de `'` para confirmar que el parámetro es vulerable:

<img width="1855" height="591" alt="image" src="https://github.com/user-attachments/assets/fdfe2c07-efe0-4e02-9a63-6ba104b6a62b" />

Al darnos un `Internal Server Error` como respuesta, confirmamos que es vulnerable a `SQLi`.


Pasos para extraer datos de una base de datos:
- Determinar el número de columnas que utiliza la consulta vulnerable (tenemos título del elemento y descripción del mismo por lo que al menos tenemos 2 columnas):
<img width="1867" height="756" alt="image" src="https://github.com/user-attachments/assets/f97cd414-3e6d-4ff0-8379-6b97b0fad245" />
Con el payload `' order by 1--` obtenemos un código 200. Probamos con `'order by 2--`:
<img width="1889" height="829" alt="image" src="https://github.com/user-attachments/assets/bc7ff03c-7c87-4c10-96c7-d1594a606cec" />
Probamos con `'order by 3--`:
<img width="1856" height="771" alt="image" src="https://github.com/user-attachments/assets/05b7be5a-2106-4311-8147-f2c5c570f44b" />
Como con 3 nos da `Internal Server Error`, sabemos que la consulta cuenta con 2 columnas.
