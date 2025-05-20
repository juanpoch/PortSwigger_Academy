# Lab: Authentication bypass via OAuth implicit flow

This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the client application makes it possible for an attacker to log in to other users' accounts without knowing their password.

To solve the lab, log in to Carlos's account. His email address is `carlos@carlos-montoya.net`.

You can log in with your own social media account using the following credentials: `wiener:peter`.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

- Iniciamos el laboratorio y nos encontramos con un blog público:
![image](https://github.com/user-attachments/assets/6ab96322-ed8d-4a44-8eab-8666d9cb392f)

- Accedemos al panel de autenticación mediante el botón `My account`, el servidor nos redirige al panel de autenticación mediante social media:
![image](https://github.com/user-attachments/assets/30b76db7-5d14-4ad4-a630-fe8ae7f3cd26)

 Esto es un simple redirect al endpoint de login social. El sitio detecta que el usuario no está autenticado, y lo redirige a iniciar sesión vía OAuth.

- Redirección al flujo OAuth:
![image](https://github.com/user-attachments/assets/075dea35-fce3-4806-b029-765354152b91)
![image](https://github.com/user-attachments/assets/4982f90d-6239-4ae3-828e-50745fa11620)

Aquí el frontend le indica al usuario que será redirigido al proveedor de identidad externo (OAuth server).

- Inicio del flujo OAuth:
![image](https://github.com/user-attachments/assets/512e3862-1e37-4bd6-8891-81b87d9bf06a)
 - `client_id`: identifica a la app cliente (el blog).

 - `redirect_uri`: adónde redirigir luego de autenticarse.

 - `response_type=token`: 👉 esto indica que estamos usando el implicit flow (el token se devolverá directamente en la URL).

 - `scope=openid profile email`: solicita acceso a información del perfil del usuario.

 El proveedor de OAuth responde con `302 Found` y una cookie llamada `_interaction` para gestionar el estado de la sesión


- Redirección a /interaction:
![image](https://github.com/user-attachments/assets/edad755c-4aae-4edd-9960-882ef4def348)

El navegador sigue la redirección, y el servidor OAuth responde con una página HTML de login del proveedor.

Este es el formulario de login de la red social simulada, donde el usuario deberá autenticarse.

- Nos autenticamos con nuestras credenciales `wiener:peter`:
![image](https://github.com/user-attachments/assets/e4ff6c93-8b31-4440-ba1b-82e487e29127)

- Nos redirige al endpoint `https://oauth-0a9c0076043a35778081151f023f0053.oauth-server.net/auth/awdq01OS9zrmYp8UqZMX4`:

![image](https://github.com/user-attachments/assets/d9fcb388-6b84-4986-8a5d-27f9fa95d278)

- Nos redirige al panel
![image](https://github.com/user-attachments/assets/9f89d3b5-ae0b-426f-aa72-0f509c0de81c)


En esta captura se muestra la interfaz de autorización que el proveedor OAuth presenta al usuario.

El proveedor de identidad (OAuth server) informa al usuario que la aplicación cliente (WeLikeToBlog) está solicitando acceso a ciertos datos del perfil. En este caso:

- 📧 Email
- 👤 Perfil

Este paso representa el **momento en que el usuario otorga consentimiento explícito** para compartir sus datos con la aplicación cliente.

🟠 Al hacer clic en **[Continue]**, el flujo avanza y el navegador será redirigido a la URL de retorno (`redirect_uri`) especificada por la app cliente, con un `access_token` incluido en el **fragmento de la URL** (es decir, después del símbolo `#`).

- Aceptamos y hacemos click en `Continue`:
![image](https://github.com/user-attachments/assets/dc319802-e073-4609-8507-58ab3b5c35d1)

- Luego de algunas redirecciones, vemos la petición GET al endpoint `/auth/awdq01OS9zrmYp8UqZMX4`:
![image](https://github.com/user-attachments/assets/34df29ec-0fdf-452a-9f6a-28f87f56fc8d)
Esta redirección devuelve el access token en el fragmento de la URL (#), típico del OAuth implicit flow.
🔎 Este fragmento no lo ve el servidor (no viaja con el request al backend), sino que es procesado por el navegador mediante JavaScript.

Nos arroja el token `access_token=hIGFosmK9wJ_3BhoQXpt4oMr6OkstLXXAiraSZ19kWm&amp`.


- Luego viene la petición al endpoint `/oauth-callback`:
![image](https://github.com/user-attachments/assets/8a40a493-0776-4ccd-8aeb-c938d6f2f309)

Que nos arroja el siguiente script:
```javascript
const token = urlSearchParams.get('access_token');
fetch('https://oauth-server.net/me', {
  headers: { Authorization: `Bearer ${token}` }
})
  .then( ... perfil del usuario ... )
  .then(() => {
    fetch('/authenticate', {
      method: 'POST',
      body: JSON.stringify({ email: j.email, username: j.sub, token })
    });
});
```

Este script es crítico para entender la vulnerabilidad:

✅ Extrae el `access_token` del fragmento `#`.

✅ Lo usa para obtener los datos del usuario autenticado (GET /me).

✅ Y luego hace un POST `/authenticate` al servidor vulnerable, enviando:

- email

- username

- token

Petición GET al endpoint `/me`:
![image](https://github.com/user-attachments/assets/aae9a382-43d8-4372-80ca-659c67084cda)

Obtiene los siguientes datos:
```json
{
  "sub": "wiener",
  "name": "Peter Wiener",
  "email": "wiener@hotdog.com",
  "email_verified": true
}
```

Confirma que el token obtenido es válido para el usuario wiener.

Pero en este laboratorio, esta respuesta es irrelevante para el servidor vulnerable, que confía únicamente en los datos del POST /authenticate enviados desde el navegador.

### 🔁 Resumen del flujo OAuth

1. `GET /my-account` → redirección a `/social-login`
2. Redirección a OAuth server → login + consentimiento
3. Redirección a `redirect_uri#access_token`
4. JavaScript envía token en `POST /authenticate`


- Petición POST al endpoint `/authenticate`:
![image](https://github.com/user-attachments/assets/218af919-bd14-4a3d-a479-c0e590993212)

Usamos los siguientes datos en el cuerpo de la solicitud:
```json
{
  "email": "wiener@hotdog.com",
  "username": "wiener",
  "token": "hIGFosmK9wJ_3BhoQXtAoMfe6KostLXXAirzSZl9kWm"
}
```
✅ Este es el request vulnerable.

🟥 En el laboratorio, el servidor acepta el campo `email` enviado por el cliente sin comprobar si corresponde al `access_token` recibido. Por lo tanto, podemos modificar el campo email por ejemplo a:

```json
{
  "email": "carlos@carlos-montoya.net",
  "username": "wiener",
  "token": "hIGFosmK9wJ_3BhoQXtAoMfe6KostLXXAirzSZl9kWm"
}
```

Enviamos la petición con el email del usuario carlos:
![image](https://github.com/user-attachments/assets/a7672cea-76c6-40c0-b944-3acbf8a21dbe)

Para resolver el laboratorio, debemos abrir el dashboard del usuario `carlos` con las cookies proporcionadas por el servidor. Para eso una forma de hacerlo es con clic derecho en la request y seleccionar `"Request in browser" > "In original session"`. Copiar esta URL y visitarla en el navegador:
![image](https://github.com/user-attachments/assets/0ba60953-fc9c-47fc-8bd1-7b5c7cd05feb)


---

---

## ✅ Comentarios finales

### 🔍 Conclusiones

- El laboratorio demuestra cómo una implementación incorrecta del flujo **OAuth Implicit** puede permitir a un atacante **suplantar la identidad de otro usuario**.
- El punto crítico fue el endpoint `/authenticate`, donde la aplicación vulnerable aceptaba cualquier combinación de `email` y `access_token` **sin verificar que el token pertenezca realmente a ese correo**.
- El token fue obtenido de forma legítima por el usuario `wiener`, pero fue reutilizado para autenticarse como `carlos`.

### 💡 Recomendaciones

- **Evitar el uso de Implicit Flow** en aplicaciones modernas. Actualmente, se recomienda usar **Authorization Code Flow con PKCE**.
- Validar del lado del servidor la identidad asociada al `access_token`, consultando directamente al proveedor OAuth (`/userinfo` o `/me`), en lugar de aceptar los datos enviados por el cliente.
- Nunca confiar en valores sensibles enviados por el frontend como el `email` del usuario.

### 📚 Lecciones aprendidas

- El fragmento `#access_token` no es visible para el servidor, solo para el navegador. Esto limita el control del backend si se confía en lo que el frontend le envía.
- Los flujos OAuth implican múltiples redirecciones por diseño, cada una cumpliendo un rol: autenticación, consentimiento, retorno seguro.
- Es clave entender **qué parte del flujo ocurre en el navegador y cuál en el servidor**, para identificar correctamente los vectores de ataque.

---



