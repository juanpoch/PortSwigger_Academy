# Lab: Authentication bypass via information disclosure

This lab's administration interface has an authentication bypass vulnerability, but it is impractical to exploit without knowledge of a custom HTTP header used by the front-end.

To solve the lab, obtain the header name then use it to bypass the lab's authentication. Access the admin interface and delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 


---


Iniciamos el laboratorio y tenemos la app de shopping, accedemos a los endpoints interceptando con Burp Suite y buscando comentarios sin encontrar nada:
![image](https://github.com/user-attachments/assets/985d86fd-5058-4134-b062-55e8560b5d9c)

Nos dirigimos a `My account` y nos logueamos con nuestras credenciales `wiener:peter`, buscando comentarios no obtenemos match:
![image](https://github.com/user-attachments/assets/b7cf1e5a-91e4-4ac9-a0ed-30b990e8eb0f)

No encontramos ningún comentario ni links ocultos.

Procedemos a buscar el panel de administración, vamos a realizar un ataque de fuerza bruta al endpoint raíz `/` utilizando `Burp Intruder` y la wordlist `common.txt` que en mi caso lo tengo en la ruta `/usr/share/SecLists/Discovery/Web-Content/common.txt`:

![image](https://github.com/user-attachments/assets/841608f1-9e74-4bdd-a914-8855e3709297)






