# Lab: SQL injection with filter bypass via XML encoding

This lab contains a SQL injection vulnerability in its stock check feature. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables.

The database contains a `users` table, which contains the usernames and passwords of registered users. To solve the lab, perform a SQL injection attack to retrieve the admin user's credentials, then log in to their account. 

`Hint`: A web application firewall (WAF) will block requests that contain obvious signs of a SQL injection attack. You'll need to find a way to obfuscate your malicious query to bypass this filter. We recommend using the Hackvertor extension to do this. 

[Hackvertor](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100)

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

---


Lanzamos el laboratorio y nos encontramos con un shop online:
<img width="1590" height="982" alt="image" src="https://github.com/user-attachments/assets/c073328a-4fe7-4097-8308-356cc5fc82b1" />

Sabemos que el laboratorio contiene una vulnerabilidad en la funcionalidad `stock check`. Los resultados de las consultas SQL son retornados en la respuesta de la aplicación, de modo que podemos realizar ataques UNION.

Hacemos click en `View Details` y observamos los detalles de un producto:
<img width="1637" height="868" alt="image" src="https://github.com/user-attachments/assets/04165d51-9255-4ec7-94c0-56720e849b96" />

Nos encontramos con la funcionalidad `Check stock`, la analizamos en Burp:
<img width="1488" height="839" alt="image" src="https://github.com/user-attachments/assets/c0e4b15e-3d76-4f4a-bed2-6f59a50ac458" />

Es una petición POST al endpoint `/product/stock` que tramita parámetros vía XML.

Hacemos un ataque UNION con el payload `UNION SELECT NULL` para detectar el número de columnas en la consulta:
<img width="1514" height="807" alt="image" src="https://github.com/user-attachments/assets/dabef6c5-01f0-46f3-b048-3093330e89c5" />

Ahora sabemos que tenemos un WAF que nos bloquea la consulta.


Ahora utilizaremos la extensión `Hackvertor`. Click derecho en el payload seleccionado -> Extensions -> Hackvertor -> Encode -> hex_entities:

<img width="1309" height="825" alt="image" src="https://github.com/user-attachments/assets/5498b0bb-fd22-4c3a-be6a-6f3bbe571d82" />

Ahora sabemos que pudimos bypassear el WAF y además confirmamos que la aplicación devuelve los resultados de la consulta.

Ahora vemos qué sucede si añadimos otro `NULL`:
<img width="1319" height="805" alt="image" src="https://github.com/user-attachments/assets/d348a912-c6b5-4440-b258-aece70ab473d" />

La aplicación no nos devuelve los resultados de la consulta, esto nos indica que no se realizó correctamente. Por lo que confirmamos que tenemos una sóla columna en la consulta.

Procedemos a filtrar la contraseña del usuario `administrator` con el payload `UNION SELECT password from users where username='administrator'`:

<img width="1499" height="833" alt="image" src="https://github.com/user-attachments/assets/cb75f6da-872e-485a-82a6-12a6440992f8" />

Contraseña: `bzugszsz1dw4f8vzsqwh`

Nos autenticamos con las credenciales `administrator`:`bzugszsz1dw4f8vzsqwh` y resolvemos el laboratorio:
<img width="1640" height="720" alt="image" src="https://github.com/user-attachments/assets/cfb8118a-a8bc-49b6-bdd0-32a6de183b28" />


