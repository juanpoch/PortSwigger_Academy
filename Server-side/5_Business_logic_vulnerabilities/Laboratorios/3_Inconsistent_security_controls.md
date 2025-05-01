# Lab: Inconsistent security controls

This lab's flawed logic allows arbitrary users to access administrative functionality that should only be available to company employees. To solve the lab, access the admin panel and delete the user `carlos`.  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)  

---

Iniciamos el lab y nos encontramos con una aplicación de shopping:
![image](https://github.com/user-attachments/assets/ed2ce9d5-9e31-44f5-8d1b-a49069a46e65)

Nosotros sabemos que tenemos que acceder al panel de administración. En un pentest normal, intentaríamos hacer fuzzing discovering mediante `Engagement tools`-> `Discover Content`, pero en este caso, intentaremos acceder al panel `/admin` manualmente:
![image](https://github.com/user-attachments/assets/1cbf9676-64dd-4512-afef-085ef7c2ca85)

Nos dice que para acceder a este endpoint, debemos ser el usuario `DontWannaCry`.

