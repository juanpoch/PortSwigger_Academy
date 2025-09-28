# Lab: SQL injection UNION attack, determining the number of columns returned by the query

This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. The first step of such an attack is to determine the number of columns that are being returned by the query. You will then use this technique in subsequent labs to construct the full attack.

To solve the lab, determine the number of columns returned by the query by performing a SQL injection UNION attack that returns an additional row containing null values. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

[SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

---


Accedemos al laboratorio y nos encontramos con un shop online:
<img width="1582" height="957" alt="image" src="https://github.com/user-attachments/assets/3f024fad-bd27-402a-9671-676d57f2b5b5" />

El laboratorio nos dice que posee una vulnerabilidad SQLi en el filtro de categoría de producto.

Objetivos:

- Determinar el número de columnas en la consulta select, realizando un ataque UNION que devuelva una fila adicional que contenga valores NULL.

---

Filtramos por alguna categoría y confirmamos que el parámetro `category` es vulnerable a `SQLi`:
<img width="1532" height="784" alt="image" src="https://github.com/user-attachments/assets/50fc9ef6-b8f4-4b61-a387-9d779977e696" />

Al darnos un `Internal Server Error` confirmamos que es vulnerable a SQLi ya que produjo un error de sintaxis.

- Procedemos a determinar el número de columnas que tiene la consulta select usando el payload `' order by 1--`:

<img width="1864" height="825" alt="image" src="https://github.com/user-attachments/assets/f7fd157b-a11a-4426-a9d8-9960fca80290" />

Usamos `' order by 2--`:  

<img width="1888" height="817" alt="image" src="https://github.com/user-attachments/assets/70eff9a9-0960-46d6-b222-f9a4c5a0b949" />  

Usamos `' order by 3--`:  

<img width="1858" height="813" alt="image" src="https://github.com/user-attachments/assets/58284f31-f0ed-47cc-9185-e4c01adb2053" />  

Probamos con `' order by 4--` y nos devuelve un `Internal Server Error`, por lo que sabemos que tenemos 3 columnas en la consulta:  

<img width="1884" height="666" alt="image" src="https://github.com/user-attachments/assets/11f2a201-5eb8-4848-8bd9-b2cec7bf310c" />  

También podemos probar con el metodo `UNION` para confirmar usando `' UNION select NULL, NULL, NULL--`:
<img width="1871" height="826" alt="image" src="https://github.com/user-attachments/assets/27ac990f-3726-4490-bdc5-b37a698da16c" />


Resolvimos el laboratorio
<img width="1584" height="911" alt="image" src="https://github.com/user-attachments/assets/90790d99-21c2-421e-8e29-8371ec21312c" />


