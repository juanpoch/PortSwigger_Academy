# Lab: Blind SQL injection with time delays and information retrieval

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows or causes an error. However, since the query is executed synchronously, it is possible to trigger conditional time delays to infer information.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.

To solve the lab, log in as the `administrator` user. 

[SQLi cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

---

Parámetro vulnerable: `TrackingId`

Objetivos: 
- Explotar una SQLi time-based para imprimir la contraseña del usuario `administrator`.
- Autenticarse como `administrator`

---

Iniciamos el laboratorio y nos encontramos con un shop online. La petición tramita el parámetro `TrackingId` el cual es vulnerable:

<img width="1502" height="810" alt="image" src="https://github.com/user-attachments/assets/70a07891-acb4-4094-8a56-7d43ec4752a8" />

