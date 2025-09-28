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

