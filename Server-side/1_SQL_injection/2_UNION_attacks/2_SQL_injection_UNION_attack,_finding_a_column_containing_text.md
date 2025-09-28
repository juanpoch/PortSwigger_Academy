# Lab: SQL injection UNION attack, finding a column containing text

This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you first need to determine the number of columns returned by the query. You can do this using a technique you learned in a previous lab. The next step is to identify a column that is compatible with string data.

The lab will provide a random value that you need to make appear within the query results. To solve the lab, perform a SQL injection UNION attack that returns an additional row containing the value provided. This technique helps you determine which columns are compatible with string data. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

[SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

---

Accedemos al laboratorio y nos encontramos con un shop online:
<img width="1404" height="969" alt="image" src="https://github.com/user-attachments/assets/9a4e6098-fa42-4c5c-9d6c-b476cbadc59d" />

El laboratorio nos dice que posee una vulnerabilidad SQLi en el filtro de categoría de producto.

Objetivos:
- Determinar el número de columnas en la consulta select, realizando un ataque UNION.
- Encontrar una columna que sea compatible con cadenas.

Filtramos por alguna categoría y confirmamos que el parámetro category es vulnerable a SQLi:
<img width="1502" height="828" alt="image" src="https://github.com/user-attachments/assets/d2dd904e-8684-45f3-a4d7-1f7e76f9bcca" />

Al darnos un `Internal Server Error` confirmamos que es vulnerable a SQLi ya que produjo un error de sintaxis.

Procedemos a determinar el número de columnas que tiene la consulta select usando el payload `' order by 1--`:
<img width="1830" height="824" alt="image" src="https://github.com/user-attachments/assets/f52093a6-0520-444d-b18b-ba83e3e85629" />

Vemos que la aplicación devuelve información, contesta con un codigo de estado 200 y además ordena el resultado.

Usamos `' order by 2--`:
<img width="1854" height="826" alt="image" src="https://github.com/user-attachments/assets/199cb83c-4f0f-4b12-a72c-bd470d8930b5" />
Vemos que la aplicación devuelve información, contesta con un codigo de estado 200 y además ordena el resultado.

Usamos `' order by 3--`:
<img width="1879" height="833" alt="image" src="https://github.com/user-attachments/assets/6ddbe6bb-9d8a-4842-9465-49bf32df9af6" />
Vemos que la aplicación devuelve información, contesta con un codigo de estado 200 y además ordena el resultado.

Probamos con `' order by 4--` y nos devuelve un `Internal Server Error`, por lo que sabemos que tenemos 3 columnas en la consulta:
<img width="1878" height="825" alt="image" src="https://github.com/user-attachments/assets/9f25864f-ee93-4f87-acdf-97ea7c0b8dde" />

También podemos probar con el metodo `UNION` para confirmar usando `' UNION select NULL, NULL, NULL--`:
<img width="1868" height="820" alt="image" src="https://github.com/user-attachments/assets/b82d8568-48cd-4843-b915-7b71c399b08a" />

