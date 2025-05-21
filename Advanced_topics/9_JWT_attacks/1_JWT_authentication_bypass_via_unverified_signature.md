# Lab: JWT authentication bypass via unverified signature

This lab uses a JWT-based mechanism for handling sessions. Due to implementation flaws, the server doesn't verify the signature of any JWTs that it receives.

To solve the lab, modify your session token to gain access to the admin panel at `/admin`, then delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

>Tip
>We recommend familiarizing yourself with [how to work with JWTs in Burp Suite](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/jwts) before attempting this lab.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y nos encontramos con un blog público:
![image](https://github.com/user-attachments/assets/03fd7b84-d95f-43bb-aff5-85b4dc9c15b0)

Accedemos al panel de autenticación mediante `My account` y nos autenticamos con nuestras credenciales `wiener:peter` para inspeccionar el mecanismo:
![image](https://github.com/user-attachments/assets/8fcd1ae1-b7b9-4d79-802a-8f538e77ca04)


En esta captura observamos que el servidor nos devuelve el `JWT`:
![image](https://github.com/user-attachments/assets/3d4d4ca2-4bd2-43c0-8f4a-dfcd43c0c9d7)


Luego tramitamos el endpoint `/my-account?id=wiener` con ese `JWT`:
![image](https://github.com/user-attachments/assets/782d0b6e-5867-4f6a-b5c9-fd1988325735)

El objetivo de este laboratorio es acceder al panel `/admin` y eliminar al usuario `carlos`. Intentamos acceder al endpoint `/admin` en el Repeater, pero no tenemos acceso al panel:
![image](https://github.com/user-attachments/assets/961e2162-2d7b-4161-a471-c9a49a9e95f1)

Accedemos a la pestaña `JSON Web Token` correspondiente a la extensión `JWT Editor` y cambiamos el valor del campo `"sub":"wiener"` por `"sub":"administrator"`:
![image](https://github.com/user-attachments/assets/2d669fc1-61bf-44af-9324-979f023c4423)

Enviamos la petición con el JWT modificado, sin una firma válida:
![image](https://github.com/user-attachments/assets/cde320ef-ab44-4852-9254-aac3331bea12)

🔍 Esta vulnerabilidad se debe a que el servidor utiliza la función `decode()` en lugar de `verify()`, lo que permite aceptar cualquier JWT sin verificar su firma. Esto permite que un atacante modifique el payload, reemplace el valor del campo `sub`, y acceda como otro usuario sin necesidad de firmar el token con una clave válida.

✏️ El claim `sub` en un JWT representa el identificador del usuario. En este caso, al cambiarlo a `administrator`, el backend nos reconoce como ese usuario sin validar si el token fue legítimamente emitido para él.

Notamos que obtuvimos acceso al panel administrativo como usuario `administrator`, por lo que tenemos disponible la funcionalidad de eliminar al usuario `carlos`.
![image](https://github.com/user-attachments/assets/75e0913f-87c3-41c9-9aac-bd685264be80)

Accedemos al endpoint `/admin/delete?username=carlos` para eliminar al usuario `carlos` y resolver el laboratorio:

![image](https://github.com/user-attachments/assets/c6bf1eb9-70f9-45b3-8744-45ab91eaae88)

![image](https://github.com/user-attachments/assets/9956aa8b-43e8-4d01-a761-bf3aec4cc9b6)

---


## ✅ Comentarios finales

### 🔍 Conclusiones

* El laboratorio demuestra una vulnerabilidad crítica causada por la **ausencia de verificación de firma en tokens JWT**.
* Esto permite que un atacante modifique libremente los datos del token (por ejemplo, el valor de `sub`) y se autentique como cualquier usuario.
* En este caso, bastó con cambiar `"sub": "wiener"` por `"sub": "administrator"` para obtener acceso al panel de administración y ejecutar acciones sensibles como eliminar usuarios.

### 💡 Recomendaciones

* Siempre utilizar funciones que **verifiquen la firma del JWT** (`verify()` en lugar de `decode()`).
* Rechazar cualquier token cuya firma no coincida o esté ausente.
* No confiar en los datos contenidos en el JWT si no se ha validado su integridad.
* Implementar controles de acceso en el backend que no dependan exclusivamente de datos manipulables por el cliente (como el `sub`).

### 📚 Lecciones aprendidas

* Los JWT no están cifrados: los datos en `header` y `payload` son legibles y modificables por cualquiera.
* La seguridad de un JWT depende exclusivamente de la firma criptográfica y de su correcta validación.
* Nunca se debe aceptar un JWT modificado si su firma no ha sido verificada con una clave segura.

---



