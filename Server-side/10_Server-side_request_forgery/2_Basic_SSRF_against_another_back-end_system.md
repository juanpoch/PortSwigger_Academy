# Lab: Basic SSRF against another back-end system

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, use the stock check functionality to scan the internal `192.168.0.X` range for an admin interface on port `8080`, then use it to delete the user `carlos`.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

La vulnerabilidad SSRF permite a un atacante manipular un servidor vulnerable para que realice solicitudes HTTP arbitrarias. En este laboratorio, se explota una funcionalidad de verificación de stock para escanear una red interna (192.168.0.X) en busca de un servicio expuesto solo para la red local. Una vez identificado el panel de administración, el atacante lo utiliza para realizar acciones no autorizadas, como eliminar usuarios.

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


El servidor nos devuelve un `400 Bad Request` y nos dice `missing parameter`.

Probamos el endpoint `192.168.0.2`:
![image](https://github.com/user-attachments/assets/dba25c51-2478-476a-a623-6679f570ae9e)
![image](https://github.com/user-attachments/assets/ebd14de8-121b-4f82-989c-b970ade0a4c5)




El laboratorio nos pide que hagamos un escaneo del rango de red `192.168.0.x` para encontrar el directorio `/admin`:
![image](https://github.com/user-attachments/assets/d54a0e2a-626a-47cd-89b3-fbd0a3b92cbe)



Hasta ahora tenemos respuestas diferenciadas en función de si el host está activo o no.


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

`Nota`: Nosotros sabíamos de la existencia de un directorio `/admin`, pero en la realidad podríamos haber enviado el endpoint al `Intruder` sin el `/admin`:  

![image](https://github.com/user-attachments/assets/82007b20-e1de-4449-9aa7-c20e180a518f)

Para ver si hay respuestas diferenciadas y reconocer el host activo (incluso se podría hacer fuerza bruta a los puertos para enumerarlos también): 

![image](https://github.com/user-attachments/assets/d4710c55-7221-4eb6-8e2d-187d9218be83)

En este caso el host 192.168.1.140 tuvo una respuesta diferente, por lo que podríamos hacer fuerza bruta a los directorios para encontrar el panel administrativo.

---

# Lab: Basic SSRF against another back-end system

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, use the stock check functionality to scan the internal `192.168.0.X` range for an admin interface on port `8080`, then use it to delete the user `carlos`.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)

---

## 🔎 Descripción general

La vulnerabilidad SSRF (Server-Side Request Forgery) permite a un atacante manipular un servidor vulnerable para que realice solicitudes HTTP arbitrarias. En este laboratorio, se explota una funcionalidad de verificación de stock para escanear una red interna (`192.168.0.X`) en busca de un servicio expuesto solo para la red local. Una vez identificado el panel de administración, el atacante lo utiliza para realizar acciones no autorizadas, como eliminar usuarios.

---

## 📅 Desarrollo paso a paso

Iniciamos el laboratorio y tenemos una aplicación de shopping:
![image](https://github.com/user-attachments/assets/cda18433-baae-4fb8-b677-1fd7208a8666)

Luego ingresamos a un producto haciendo click en `View details`:
![image](https://github.com/user-attachments/assets/7cbf72ab-e476-459b-a448-246f0078d339)

Usamos la funcionalidad de `Check stock` y notamos que el servidor responde con `992` unidades:
![image](https://github.com/user-attachments/assets/448f3e43-b533-4683-8fb2-64c14873cc0e)

La aplicación es similar al lab anterior: un sistema de compras con verificación de stock por producto. El parámetro `stockApi` puede ser manipulado para que el servidor consulte URLs arbitrarias.

### 🚨 Exploración interna (SSRF Scan)

Comenzamos testeando el host `192.168.0.1:8080`:

```bash
stockApi=http%3A%2F%2F192.168.0.1%3A8080
```

Respuesta: `400 Bad Request` – servicio activo, pero con parámetros faltantes.

Probamos `192.168.0.2`, `192.168.0.3`, etc., hasta encontrar uno que responda con `200 OK`.

Para automatizar esta tarea:

* Enviamos la petición al `Intruder`
* Configuramos el payload como rango de `192.168.0.1` a `192.168.0.255`
* Ejecutamos el ataque

🔍 Identificamos que el host `192.168.0.188` devuelve `200 OK`.

### 🌐 Acceso al panel administrativo interno

Enviamos la siguiente solicitud:

```bash
stockApi=http%3A%2F%2F192.168.0.188%3A8080%2Fadmin
```

Esto revela el panel de administración, incluyendo la lista de usuarios.

Buscamos en el código fuente y encontramos:

```text
/admin/delete?username=carlos
```

Accedemos a:

```bash
stockApi=http%3A%2F%2F192.168.0.188%3A8080%2Fadmin%2Fdelete%3Fusername%3Dcarlos
```

El servidor responde con `302 Found` indicando la eliminación exitosa del usuario.

🏆 Laboratorio resuelto.

---

## 🔹 Conclusiones

Este laboratorio demuestra cómo una funcionalidad aparentemente inofensiva (verificación de stock) puede permitir a un atacante escanear una red interna y comprometer componentes críticos como interfaces administrativas.

La confianza implícita en las solicitudes desde el servidor es una mala práctica que puede derivar en:

* Bypass de controles de acceso
* Acceso a sistemas internos
* Acciones no autorizadas (como eliminar usuarios)

---

## 🧰 Recomendaciones

* Nunca confíes en URLs definidas por el usuario sin validación estricta
* Implementar listas blancas de destinos permitidos para solicitudes salientes
* Asegurar que los servicios internos no confíen solo en la IP de origen para autenticar

---

## 📃 Lecciones aprendidas

* Los entornos internos no deben ser considerados seguros por defecto
* Las SSRF pueden ser utilizadas como herramienta de reconocimiento interno
* Burp Intruder es útil para escanear rangos internos en este tipo de ataques
* El comportamiento HTTP (`200`, `400`, `500`) puede usarse como canal lateral para detectar servicios vivos

---



