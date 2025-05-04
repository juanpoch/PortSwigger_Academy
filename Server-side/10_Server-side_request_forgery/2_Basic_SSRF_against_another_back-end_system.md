# Lab: Basic SSRF against another back-end system

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, use the stock check functionality to scan the internal `192.168.0.X` range for an admin interface on port `8080`, then use it to delete the user `carlos`.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y tenemos una aplicación de shopping:
![image](https://github.com/user-attachments/assets/cda18433-baae-4fb8-b677-1fd7208a8666)


Luego ingresamos a un producto haciendo click en `View details`:
![image](https://github.com/user-attachments/assets/7cbf72ab-e476-459b-a448-246f0078d339)


Usamos la funcionalidad de `Check stock` para inspeccionarla con Burp Suite y notamos que el servidor nos responde con `992` unidades de stock:
![image](https://github.com/user-attachments/assets/448f3e43-b533-4683-8fb2-64c14873cc0e)



La aplicación es similar al lab anterior: un sistema de compras con verificación de stock por producto.
Por lo que otra vez tenemos un vector de potencial SSRF, ya que la aplicación está confiando en el parámetro `stockApi` para dirijirse a una URL que valida el stock del producto.


Como el laboratorio dice que tenemos que escanear el rango interno `192.168.0.X`, procedemos a ver si tenemos acceso al endpoint `http://192.168.0.1:8080`:
![image](https://github.com/user-attachments/assets/ff226a48-b025-4f90-8c93-de4e4a80c860)


Si bien nos dice `missing parameter`, el laboratorio nos pide que escaniemos el rango re red `192.168.0.x` para encontrar el directorio `/admin`:
![image](https://github.com/user-attachments/assets/d54a0e2a-626a-47cd-89b3-fbd0a3b92cbe)

Probamos el endpoint `192.168.0.2`:
![image](https://github.com/user-attachments/assets/115dbbd7-9046-4377-9a73-9d6fb1e812c5)


Si probamos la dirección `192.168.0.1` nos lanza una respuesta `500 Internal Server Error`:
![image](https://github.com/user-attachments/assets/ac6f987d-c9c8-451e-9fa5-aa7add867cfa)

![image](https://github.com/user-attachments/assets/5a2818aa-82ba-48e5-8dc7-705c7abe40ed)

Por lo que tenemos respuestas diferenciadas en función de si el host está activo o no.


Enviamos la petición anterior al `Intruder` para realizar fuerza bruta de hosts:
![image](https://github.com/user-attachments/assets/f80e551d-9996-4e9b-8d03-888039033a37)


Realizamos el ataque:
![image](https://github.com/user-attachments/assets/2490b1b1-4468-4e0f-94e5-049dcf4c7e1e)

Vemos que el endpoint `192.168.0.188` arroja un `200 OK` y nos permite ingresar al panel de administración, mediante el cual podríamos eliminar usuarios.

Accedemos al endpoint `http://192.168.0.188:8080/admin` y filtramos en el código fuente por `carlos`. Encontramos el enlace `http://192.168.0.188:8080/admin/delete?username=carlos` para eliminar su usuario :

![image](https://github.com/user-attachments/assets/748d18ef-8cf9-49a5-8bfc-417b7ba4fc37)

Accedemos al endpoint para eliminar el usuario `carlos`:
![image](https://github.com/user-attachments/assets/4f5b5434-e4e7-481a-a08d-0fa789e1b86e)

Nos responde con un `302 Found` lo cual es un redirect hacia el panel de administración `http://192.168.0.188:8080/admin` a estas alturas ya resolvimos el laboratorio, insertamos la dirección al panel administrativo en el payload para visualizar el banner:

![image](https://github.com/user-attachments/assets/6c8b00f4-2f54-452b-ba08-202112a45abd)


---
