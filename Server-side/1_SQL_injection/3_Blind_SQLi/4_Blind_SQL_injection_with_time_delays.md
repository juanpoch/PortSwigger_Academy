# Lab: Blind SQL injection with time delays

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows or causes an error. However, since the query is executed synchronously, it is possible to trigger conditional time delays to infer information.

To solve the lab, exploit the SQL injection vulnerability to cause a 10 second delay. 

[SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

---


`Parámetro vulnerable`: `TrackingId`.

Objetivo: Explotar una time-based SQLi que genere un delay de 10 segundos.


---

Iniciamos el laboratorio y nos encontramos con un shop online, que tramita la custom cookie `TrackingId`, la cual sabemos que es vulnerable:
<img width="1520" height="951" alt="image" src="https://github.com/user-attachments/assets/77e28a6d-c1db-4118-8cd6-c02b83c8712f" />

Debido a que no conocemos qué motor de base de datos tenemos en frente, procedemos a probar un payload a la vez para cada uno, utilizando nuestra `Cheat sheet`.

Comenzamos con el payload `' || (SELECT SLEEP(10))` correspondiente a `MySql`:
<img width="1909" height="891" alt="image" src="https://github.com/user-attachments/assets/83774541-853b-440f-8153-decfd71637ed" />


Vemos que contesta rápidamente, cuando la consulta original tarda 234 millis.

Continuamos con el payload `' || (SELECT pg_sleep(10))` correspondiente a `PostgreSql`:
<img width="1913" height="864" alt="image" src="https://github.com/user-attachments/assets/bf023eaa-2e49-4b88-813f-1b63f5e6c0ce" />

La consulta seguramente es del estilo:
```sql
select trackingId from trackingTable where trackingId='<id>'
```
Debemos añadir un comentario `--` al final para que la sintaxis no quede rota.


Probamos nuevamente con el payload `' || (SELECT pg_sleep(10)) --` correspondiente a `PostgreSql`:
<img width="1909" height="857" alt="image" src="https://github.com/user-attachments/assets/eb1b2045-6338-4017-90f5-88ed56b302a3" />

Tardó 10 segundos, por lo que resolvimos el laboratorio:
<img width="1656" height="909" alt="image" src="https://github.com/user-attachments/assets/6314a58a-6254-4a63-8658-c8ae4b1dc45b" />

