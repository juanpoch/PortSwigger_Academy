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

- Nos redirije al endpoint `https://oauth-0a9c0076043a35778081151f023f0053.oauth-server.net/auth/awdq01OS9zrmYp8UqZMX4`:

![image](https://github.com/user-attachments/assets/d9fcb388-6b84-4986-8a5d-27f9fa95d278)

- Nos redirije al panel
![image](https://github.com/user-attachments/assets/9f89d3b5-ae0b-426f-aa72-0f509c0de81c)

Esta última captura muestra la respuesta final del proveedor OAuth después de haber completado todo el proceso de autenticación, justo antes de redirigir al usuario nuevamente al cliente (el blog).
El contenido del body es una página HTML que contiene el formulario final de redirección del flujo OAuth. Esta respuesta incluye el HTML con los estilos y el frontend necesario para que el JavaScript del navegador extraiga el access token (cuando sea el momento) y lo incluya en una redirección al cliente.

Sin embargo, no estás viendo todavía el access token, porque como es un Implicit Flow, ese token vendrá en un fragmento #access_token=... que:

No es visible para el servidor, solo para el navegador.

Será manejado por JavaScript, que hará luego el POST /authenticate hacia la aplicación.

Aceptamos y hacemos click en `Continue`


















## Análisis de captura OAuth 2.0 - Grant Type: Implicit

Esta captura representa un flujo OAuth 2.0 utilizando el grant type **implicit**, que es un tipo de autorización común en aplicaciones del lado del cliente (como SPA - Single Page Applications) pero con importantes implicancias de seguridad.

---

### 📂 Request:

```http
GET /auth?
client_id=ru15c4...fzdg
&redirect_uri=https://0a99009704ddab7c8265b12900d400dd.web-security-academy.net/oauth-callback
&response_type=token
&nonce=...
&scope=openid%20profile%20email
```

#### Campos importantes:

* `client_id`: identificador único de la aplicación cliente.
* `redirect_uri`: URI donde se redirigirá al usuario tras completar la autorización. **Es crítico validarlo adecuadamente para evitar ataques como token leakage.**
* `response_type=token`: indica que se está usando el **implicit flow** (sin código de autorización intermedio).
* `scope`: se está solicitando acceso al `openid`, `profile`, y `email` del usuario.

---

### 📥 Response:

```http
HTTP/2 302 Found
Location: /interaction/BsxAB9ITORLl8gR52_2tn
```

El servidor nos redirige al panel de login:
![image](https://github.com/user-attachments/assets/c4e7eab6-303e-48aa-9d7d-5da9bc4c525a)

Nos autenticamos con nuestras credenciales `wiener:peter`
![image](https://github.com/user-attachments/assets/f4458ee9-4448-430f-870b-477f444b7674)
![image](https://github.com/user-attachments/assets/cb1ad96a-513d-4308-8d78-ca629743612e)



![image](https://github.com/user-attachments/assets/ac9cd0fb-3837-483c-ae39-0ba66ad2c5b1)



La aplicación nos solicita autorizar su acceso a nuestro perfil y email:
![image](https://github.com/user-attachments/assets/b4488913-fcdd-4a75-92b2-0cc9500f1fa6)

Por lo que aceptamos haciendo clic en `Continue`:


Vemos que se tramita una solicitud POST al endpoint `/authenticate` con los siguientes datos:
```json
{"email":"wiener@hotdog.com","username":"wiener","token":"S-E6OGelo7ngSiSaKGJcaRLDfIKiwSXv38rgYWQ_QIn"}
```

- Se está enviando un `access_token` directamente en el cuerpo `JSON` junto con `username` y `email`.

- Esto es típico de un flujo `OAuth Implicit` o una mala implementación del `Authorization Code Flow`, donde el cliente almacena el token en el navegador y luego lo reutiliza para autenticarse.

El servidor nos responde con la siguiente cookie de sesión: `2Iwx9sYwwm7NmI7IOXZ6TRzusBZhcy8c`, lo que indica que nos autenticamos correctamente.


Si no existe ningún tipo de validación entre el token y los datos, y a su vez se permite la reutilización del token, podremos usar la dirección de email del usuario carlos (`carlos@carlos-montoya.net`) e intentar autenticarnos como tal:
![image](https://github.com/user-attachments/assets/1fdf1321-9ce4-40f2-a948-24230995a202)

Para resolver el laboratorio, debemos abrir el dashboard del usuario `carlos` con las cookies proporcionadas por el servidor. Para eso una forma de hacerlo es con clic derecho on la request and seleccionar `"Request in browser" > "In original session"`. Copiar esta URL y visitarla en el navegador:
![image](https://github.com/user-attachments/assets/4ba7e744-3219-45bd-b625-3c170d123ddd)

---


  


