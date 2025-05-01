# Lab: User role controlled by request parameter

This lab has an admin panel at `/admin`, which identifies administrators using a forgeable cookie.

Solve the lab by accessing the admin panel and using it to delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y nos encontramos con la típica aplicación de shopping:
![image](https://github.com/user-attachments/assets/49dcf151-80e2-4201-a5bb-5adbfb8086bf)


Accedemos al panel de login y nos autenticamos con nuestras credenciales `wiener:peter` con el fin de analizar el flujo, ya que en algún momento nos encontraremos con una cookie interesante:

![image](https://github.com/user-attachments/assets/313c582b-b244-4426-b6ef-0e2391f51ce2)

La siguiente petición corresponde al proceso de autenticación:  

![image](https://github.com/user-attachments/assets/0d03e7ce-c383-402b-a0f7-70fb61d75712)  


Esta respuesta HTTP revela una vulnerabilidad muy crítica relacionada con control de acceso basado en parámetros manipulables por el cliente, en este caso mediante una cookie llamada Admin.

Esto sugiere que el sistema determina si un usuario tiene privilegios de administrador basándose en el valor de esa cookie, lo cual representa una violación al principio de confianza cero en el cliente.

Este es un clásico ejemplo de control de acceso basado en parámetros del lado cliente.


Luego ingresamos al dashboard principal del usuario:
![image](https://github.com/user-attachments/assets/12dee1a1-b66d-40f6-927d-c699d99ab105)


Enviamos el endpoint `/my-account?id=wiener` al `Repeater` y cambiamos el valor de la cookie a `Admin=true`, vemos que tenemos acceso al panel de administración sin ningún tipo de restricción:
![image](https://github.com/user-attachments/assets/422cd446-93d6-45f4-a50e-b32cbd9e767b)

Buscamos el link del panel de administración en el código fuente:
![image](https://github.com/user-attachments/assets/98bd6a4e-de15-4820-979e-127054c5830b)


Accedemos al panel `/admin` modificando la petición anterior, vemos que tenemos acceso a la funcionalidad de eliminar usuarios:
![image](https://github.com/user-attachments/assets/088182be-b2da-4130-a32b-1342b818f531)

Buscamos el endpoint de eliminar al usuario carlos en el código fuente:
![image](https://github.com/user-attachments/assets/941c2a34-5e63-45e8-8a65-c4d39071d476)

Accedemos al endpoint `/admin/delete?username=carlos` para eliminar al usuario `carlos` y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/988e2c0e-97cb-4a9c-8d3c-4ba090080a04)

![image](https://github.com/user-attachments/assets/d6cbc124-367c-43ac-8d3c-003abb72e97e)

---

## ✅ Conclusión

Se identificó y explotó correctamente una vulnerabilidad de **escalada vertical de privilegios** debido a un mecanismo de autorización basado en una **cookie manipulable por el cliente**. La aplicación determinaba si un usuario era administrador en base a la cookie `Admin=true`, sin realizar validaciones adicionales del lado del servidor.

Esto permitió acceder al panel de administración (`/admin`) y utilizar funcionalidades críticas como la eliminación de usuarios, sin contar con los permisos correspondientes.

## 🛡️ Recomendaciones

- Nunca se debe confiar en valores enviados por el cliente (cookies, parámetros GET o POST) para determinar privilegios o roles.
- Implementar validaciones sólidas del lado del servidor que consulten el rol del usuario autenticado a través de sesiones o tokens firmados.
- Evitar exponer roles, banderas o atributos sensibles en cookies no cifradas o no firmadas.
- Usar mecanismos de control de acceso centralizados, con verificación segura en cada solicitud a funciones sensibles.

## 📚 Lecciones aprendidas

- Una cookie como `Admin=false` puede ser una pista directa de un control de acceso mal implementado.
- El método `Repeater` de Burp Suite es fundamental para modificar valores y testear comportamientos sin restricciones del navegador.
- La lógica de privilegios debe estar validada **únicamente del lado del servidor**.
- Acciones críticas como eliminar usuarios deben estar protegidas por múltiples capas de control, incluyendo autenticación, autorización y validación de sesión.











