# Lab: User role can be modified in user profile

This lab has an admin panel at `/admin`. It's only accessible to logged-in users with a `roleid` of 2.

Solve the lab by accessing the admin panel and using it to delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Accedemos al laboratorio y nos encontramos con la típica aplicación de shopping:

![image](https://github.com/user-attachments/assets/8b18024d-93e1-43ae-8ecc-f29841e33346)

Accedemos al panel de login utilizando el botón `My account` y nos logueamos con nuestras credenciales `wiener:peter` mientras analizamos el flujo:
![image](https://github.com/user-attachments/assets/9a8ab87b-e5a0-4fbc-b77e-47db7f5f5e5e)

Cuando nos logueamos tenemos la típica petición post:
![image](https://github.com/user-attachments/assets/4ed6b183-e872-4866-9188-8d1322c28559)

Dashboard del usuario:
![image](https://github.com/user-attachments/assets/167f809e-f2c3-4249-a4ce-b91b82addcd3)

Podríamos enviar la petición al `Repeater` e intentar cambiar el parámetro `id`, pero vemos que no aparenta ser vulnerable:
![image](https://github.com/user-attachments/assets/2f0cc00e-b574-4fdb-aa41-af14fbced106)

Aún tenemos la funcionalidad de `update email`:
![image](https://github.com/user-attachments/assets/32fbe253-8f49-4600-aff9-c66718e02d28)

Cambiamos nuestro mail para analizar el flujo:
![image](https://github.com/user-attachments/assets/1c311f79-5c60-42d6-8307-7f20f8b008bf)

Esto es una clara exposición de información sensible en una respuesta HTTP, y podría facilitar una escalada de privilegios basada en parámetros si no hay validaciones del lado del servidor.


Agregamos el parámetro `roleid:2` y vemos que podemos reasignarlo:
![image](https://github.com/user-attachments/assets/a395c9da-bced-426d-b927-2180c94d0e11)

Permitir que un atributo como roleid sea enviado por el cliente y que eso afecte directamente el nivel de acceso rompe por completo el principio de "servidor como fuente de verdad" y representa una seria violación de seguridad.

Hacemos click en `Follow redirection` en el `Repeater` para ir a `My Account`, observamos que tenemos acceso al panel de administración:
![image](https://github.com/user-attachments/assets/d3b24ce1-4820-4f66-86c2-817f9b0a8887)

Buscamos el enlace al panel de administración y accedemos al mismo:
![image](https://github.com/user-attachments/assets/7d69ec72-1f89-42bc-b9ba-c00d211a922f)

Accedimos al panel de administración, y vemos que tenemos acceso al endpoint de eliminación de usuarios de `carlos`:
![image](https://github.com/user-attachments/assets/da43127e-f092-4aa3-9d1c-68833170e06f)

Accedemos al endpoint `/admin/delete?username=carlos` para eliminar el usuario `carlos` y resolver el laboratorio:
![image](https://github.com/user-attachments/assets/9062aa68-f92a-4482-93ce-9ea8c7df5e16)

Hacemos click en `Follow redirection` para acceder al endpoint `My account` y mostrar el laboratorio resuelto:
![image](https://github.com/user-attachments/assets/2b9c1f71-5625-49a7-9689-09f1a72307d7)

---

## ✅ Conclusión

Se identificó y explotó exitosamente una vulnerabilidad de **escalada de privilegios vertical** debido a un control de acceso mal implementado basado en parámetros del cliente.  
En este caso, la aplicación permitía modificar el valor del campo `roleid` en una solicitud de cambio de email, lo que habilitó al atacante a escalar de un rol normal (`roleid=1`) a un rol de administrador (`roleid=2`) sin validación del lado servidor.

Este tipo de vulnerabilidad demuestra una **confianza inapropiada en datos enviados por el cliente**, rompiendo los principios de seguridad de control de acceso, donde las decisiones deben ser siempre controladas y verificadas por el servidor.

---

## 🛡️ Recomendaciones

- El servidor **nunca debe confiar en valores sensibles enviados por el cliente**, como roles o permisos.
- Los controles de acceso deben aplicarse del lado servidor, y los atributos como `roleid` deben obtenerse exclusivamente desde la sesión del usuario autenticado.
- Implementar **verificaciones robustas** al modificar atributos relacionados con privilegios.
- Realizar pruebas automatizadas de acceso no autorizado como parte del pipeline de CI/CD.
- Registrar y monitorear cambios inesperados en parámetros relacionados a roles o privilegios.

---

## 📚 Lecciones aprendidas

- Una cabecera o parámetro como `roleid`, si no está validado, puede ser una **puerta abierta a funciones críticas**.
- Las vulnerabilidades de escalada vertical permiten a usuarios comunes acceder a recursos administrativos si no hay controles de autorización sólidos.
- Es esencial **validar toda modificación de perfil** en función del usuario autenticado real, no del contenido enviado en la petición.


