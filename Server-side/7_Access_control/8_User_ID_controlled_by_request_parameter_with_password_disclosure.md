# Lab: User ID controlled by request parameter with password disclosure

This lab has user account page that contains the current user's existing password, prefilled in a masked input.

To solve the lab, retrieve the administrator's password, then use it to delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---


Accedemos al laboratorio y nos encontramos con una aplicación de shopping:
![image](https://github.com/user-attachments/assets/13d4c975-4398-45fe-bd10-c64613bfc97c)

Accedemos al panel de autenticación mediante el botón `My account` y nos autenticamos con nuestras credenciales `wiener:peter`:
![image](https://github.com/user-attachments/assets/2f192fc2-9ebd-42d6-8359-5d2249b6ec79)

En el dashboard del usuario, vemos dos funcionalidades, la de `Update email` y la de `Update password`. El campo de la contraseña ya tiene una vulberabilidad en sí misma, ya que refleja el valor de la contraseña actual en el DOM, lo cual podría llevar a vulnerabilidades de XSS.

Petición en Burp Suite:
![image](https://github.com/user-attachments/assets/22c4487e-e655-4d45-80ce-7b0df7958f78)

Enviamos esta petición al `Repeater` y cambiamos el valor del parámetro `id=wiener` por `id=administrator`:
![image](https://github.com/user-attachments/assets/340cd4ad-79bc-4bbf-b7e0-dfb0a63910c6)

Esta petición muestra un grave caso de escalada de privilegios horizontal convertida en vertical mediante IDOR, con exposición directa de una contraseña en el cuerpo de la respuesta HTML.

### Vulnerabilidades detectadas:

- IDOR con parámetro id sin validación de sesión.

- Exposición de contraseña en texto plano.

- Broken Access Control (escalada horizontal → vertical).

- Posible Stored XSS si el campo es editable y reflejado sin sanitización.

Procedemos a autenticarnos como `administrator` utilizando las credenciales `administrator:wfwc2fxopau0yl14apqx`:
![image](https://github.com/user-attachments/assets/a31bf41d-2078-41a4-818b-524a356446a4)

Notamos que nos podemos autenticar correctamente, accedemos al panel administrativo y vemos que tenemos la capacidad de eliminar usuarios:
![image](https://github.com/user-attachments/assets/ec4449c7-e2ea-451f-8cc5-cffee7e0b83a)

Eliminamos el usuario `carlos` y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/bb560655-0dec-45d8-aa18-398d32193284)

---

## ✅ Conclusión

Se identificó una vulnerabilidad de tipo **IDOR** que, al no validar correctamente la identidad del usuario autenticado, permitió acceder a la cuenta del usuario `administrator` manipulando el parámetro `id`. Como consecuencia de esto, se reveló en el HTML la contraseña precargada del administrador, lo que derivó en una **escalada vertical de privilegios**. Esta exposición crítica permitió autenticarse como administrador y acceder al panel `/admin`, desde donde fue posible eliminar al usuario `carlos`, cumpliendo con el objetivo del laboratorio.

---

## 🛡️ Recomendaciones

- Nunca prellenar campos de contraseña en formularios HTML con valores reales, ni siquiera si están enmascarados con `type="password"`.
- Implementar validaciones del lado servidor que impidan que un usuario acceda o modifique recursos que no le pertenecen (por ejemplo, validando que `id` coincida con el usuario autenticado).
- Utilizar identificadores internos no predecibles combinados con controles de acceso robustos, evitando confiar únicamente en parámetros GET.
- Aplicar el principio de **mínima exposición de datos**: evitar reflejar información sensible innecesariamente en el frontend.

---

## 📚 Lecciones aprendidas

- Una vulnerabilidad aparentemente simple como un **IDOR** puede convertirse en una falla crítica si se combina con una **exposición de datos sensibles**, como contraseñas.
- Los formularios que cargan datos del servidor deben ser auditados con atención, especialmente cuando contienen campos sensibles como contraseñas, claves API u otros secretos.
- Las pruebas de control de acceso no deben limitarse a probar accesos bloqueados: también deben verificar si se filtra información sensible en redirecciones, campos ocultos o elementos precargados.
- Las vulnerabilidades horizontales pueden ser un punto de entrada para una **escalada vertical de privilegios**, si se apunta a usuarios con roles superiores.

---


