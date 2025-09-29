# Lab: Blind SQL injection with conditional responses

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and no error messages are displayed. But the application includes a `Welcome back` message in the page if the query returns any rows.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.

To solve the lab, log in as the `administrator` user. 

`Hint`: You can assume that the password only contains lowercase, alphanumeric characters. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

[SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)


---




Objetivos:

- Enumerar la contraseña del administrador.
- Autenticarse como `administrator`.

Accedemos al laboratorio y nos encontramos con un shop online:
<img width="1585" height="974" alt="image" src="https://github.com/user-attachments/assets/cd7d468b-ef98-4f78-9056-634a6f7bddc8" />
