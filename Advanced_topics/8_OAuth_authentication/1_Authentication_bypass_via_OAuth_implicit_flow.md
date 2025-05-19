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
Location: https://.../oauth-callback#access_token=JzDp...&token_type=Bearer&scope=openid%20profile%20email
```

El servidor responde con un redireccionamiento (`302 Found`) hacia el `redirect_uri`, **incluyendo el ********`access_token`******** en el fragmento de URL** (lo que viene después de `#`).

#### Importante:

* El `access_token` **no se envía al servidor**, ya que el fragmento no forma parte de la petición HTTP. Solo el navegador lo puede leer.
* Esto obliga a que la aplicación cliente use **JavaScript** para capturar el `access_token`.

---

### ⚠️ Riesgos del Implicit Flow

| Riesgo                                        | Descripción                                                                                                  |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Token en URL fragment                         | Cualquier código JS que corra en el contexto de la página puede acceder al token si no hay CSP estricta.     |
| No hay canal seguro servidor-servidor         | El `access_token` se expone directamente al navegador.                                                       |
| No se usa `client_secret`                     | Lo que limita la validación del cliente.                                                                     |
| Posible exposición por redirecciones abiertas | Si el `redirect_uri` está mal validado, el token podría ser enviado a un dominio controlado por un atacante. |

![image](https://github.com/user-attachments/assets/ac9cd0fb-3837-483c-ae39-0ba66ad2c5b1)

Nos autenticamos con nuestras credenciales `wiener:peter`:
![image](https://github.com/user-attachments/assets/ddf98926-9cf4-4f9d-880a-d211bb28d0d9)

La aplicación nos solicita autorizar su acceso a nuestro perfil y email, por lo que aceptamos haciendo clic en `Continue`:
![image](https://github.com/user-attachments/assets/bc042af2-5e13-418c-a910-8bd35f8b4b2e)

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


  


