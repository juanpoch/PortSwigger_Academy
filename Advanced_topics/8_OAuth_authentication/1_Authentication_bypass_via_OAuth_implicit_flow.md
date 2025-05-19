# Lab: Authentication bypass via OAuth implicit flow

This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the client application makes it possible for an attacker to log in to other users' accounts without knowing their password.

To solve the lab, log in to Carlos's account. His email address is `carlos@carlos-montoya.net`.

You can log in with your own social media account using the following credentials: `wiener:peter`.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y nos encontramos con un blog público:
![image](https://github.com/user-attachments/assets/6ab96322-ed8d-4a44-8eab-8666d9cb392f)

Accedemos al panel de autenticación mediante el botón `My account`, el servidor nos redirige al panel de autenticación mediante social media:
![image](https://github.com/user-attachments/assets/12741918-7ba6-4dd3-8807-bebcf0b17cdd)
![image](https://github.com/user-attachments/assets/0016b9fa-55ed-4296-ae28-c81bbd8effdb)
Se tramita automáticamente la siguiente petición:
![image](https://github.com/user-attachments/assets/13b64989-424c-4530-a1c7-d872777ea8ed)


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


  


