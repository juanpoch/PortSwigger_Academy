# Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft

This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.

To solve the lab, display the database version string. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

[SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

---

Iniciamos el laboratorio y nos encontramos un shop online. El laboratorio tiene una vulnerabilidad de `SQLi` en el filtro de categoría de producto.

<img width="1414" height="976" alt="image" src="https://github.com/user-attachments/assets/2a71b7a8-36a3-4a1d-b0a6-2abfa641c953" />

Procedemos a probar inyectar `'` en el parámetro `category`:
<img width="1777" height="761" alt="image" src="https://github.com/user-attachments/assets/634bda37-210c-4809-8a17-a3e5ac9595fc" />

Al darnos un `Internal Server Error` confirmamos que es vulnerable a `SQLi`.


- Determinar el número de columnas que utiliza la consulta vulnerable (tenemos título del elemento y descripción del mismo por lo que al menos tenemos 2 columnas):
<img width="1877" height="549" alt="image" src="https://github.com/user-attachments/assets/ab003c52-9dc3-4e23-b854-1ccf6e17d00d" />

Obtenemos un `Internal Server Error`, eso es porque hay algún caracter que no está procesando, probemos con `#`:
<img width="1871" height="733" alt="image" src="https://github.com/user-attachments/assets/5185255e-a082-4455-862d-eae0e0b34939" />




