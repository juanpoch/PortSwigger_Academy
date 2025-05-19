# OAuth Grant Types

OAuth 2.0 define una serie de "grant types" (tipos de concesión) que representan los diferentes flujos de autorización posibles entre un usuario, una aplicación cliente y el proveedor OAuth.

A continuación se explican en detalle los dos tipos de flujo más comunes:

---

## 📃 ¿Qué es un OAuth Grant Type?

El grant type determina la secuencia exacta de pasos en el proceso de autorización OAuth, así como la forma en que la aplicación cliente se comunica con el servidor OAuth y obtiene el access token.

Algunos grant types están diseñados para aplicaciones con un servidor back-end seguro, mientras que otros están destinados a aplicaciones del lado del cliente (como SPAs o apps móviles).

---

## ⚖️ Scopes en OAuth

El parámetro `scope` especifica los permisos o tipos de datos a los que la aplicación cliente desea acceder. Algunos ejemplos:

| Scope                                             | Significado                                          |
| ------------------------------------------------- | ---------------------------------------------------- |
| `openid`                                          | Indica que se desea usar OpenID Connect              |
| `profile`                                         | Solicita información básica del usuario              |
| `email`                                           | Acceso al correo electrónico del usuario             |
| `contacts.read`                                   | Lectura de la lista de contactos                     |
| `https://api.site.com/auth/scopes/drive.readonly` | Acceso a Google Drive solo de lectura (ejemplo real) |

---

## ⚡ Authorization Code Grant Type (código de autorización)

Este flujo está pensado para aplicaciones que pueden almacenar el `client_secret` de forma segura. Es el más seguro y recomendado para aplicaciones del lado del servidor.

### Etapas:

#### 1. Petición de autorización (authorization request)

```http
GET /authorization?
  client_id=12345
  &redirect_uri=https://client-app.com/callback
  &response_type=code
  &scope=openid%20profile
  &state=ae13d489bd00e3c24
```

* `client_id`: Identificador de la aplicación cliente
* `redirect_uri`: Dónde redirigir al usuario tras la autorización
* `response_type=code`: Solicita un código de autorización
* `state`: Previene ataques CSRF

#### 2. Login del usuario y consentimiento

El usuario inicia sesión en el proveedor (por ejemplo, su cuenta de Google) y acepta (o no) los permisos solicitados por el `scope`.

#### 3. Redirección con authorization code

```http
GET /callback?code=a1b2c3&state=ae13d489bd00e3c24
```

#### 4. Solicitud de token (access token request)

```http
POST /token
Host: oauth-provider.com

client_id=12345
client_secret=SECRET
redirect_uri=https://client-app.com/callback
grant_type=authorization_code
code=a1b2c3
```

#### 5. Respuesta con access token

```json
{
  "access_token": "z0y9x8w7v6u5",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile"
}
```

#### 6. API call a /userinfo

```http
GET /userinfo
Authorization: Bearer z0y9x8w7v6u5
```

#### 7. Respuesta con datos del usuario

```json
{
  "username": "carlos",
  "email": "carlos@example.com"
}
```

---

## 🚫 Implicit Grant Type

Este tipo de flujo es menos seguro y está diseñado para aplicaciones del lado del cliente (JavaScript puro, móviles, etc.), donde no se puede almacenar el `client_secret`.

### Diferencias principales:

* El token se devuelve directamente en la redirección
* Todo ocurre en el navegador, sin canal seguro servidor-servidor

### Etapas:

#### 1. Petición de autorización

```http
GET /authorization?
  client_id=12345
  &redirect_uri=https://client-app.com/callback
  &response_type=token
  &scope=openid%20profile
  &state=ae13d489bd00e3c24
```

#### 2. Login del usuario y consentimiento

#### 3. Redirección con token (fragmento URL)

```http
GET /callback#access_token=z0y9x8w7v6u5&token_type=Bearer&scope=openid profile
```

El access token no se envía al servidor directamente. El front-end debe extraerlo de la URL.

#### 4. API call

```http
GET /userinfo
Authorization: Bearer z0y9x8w7v6u5
```

#### 5. Respuesta con datos del usuario

---

## 🔄 Tabla comparativa

| Aspecto                        | Authorization Code Flow | Implicit Flow        |
| ------------------------------ | ----------------------- | -------------------- |
| Seguridad                      | Alta                    | Baja                 |
| Ideal para                     | Back-ends               | SPAs, apps móviles   |
| Requiere client\_secret        | Sí                      | No                   |
| Canal seguro servidor-servidor | Sí                      | No                   |
| Uso común                      | Login social, APIs      | Apps JS sin servidor |

---

## 📁 Recomendaciones modernas

* **Evitar Implicit Flow**: Actualmente se recomienda `Authorization Code with PKCE` incluso en aplicaciones SPAs.
* **Implementar validación de \*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*`state`**: Para prevenir ataques CSRF.
* **Verificar audiencia y scopes**: El token recibido debe ser validado.
* **No exponer tokens en URLs**: Pueden filtrarse en logs o referers.

---

## 📃 Lecturas recomendadas

* [RFC 6749 - OAuth 2.0 Framework](https://datatracker.ietf.org/doc/html/rfc6749)
* [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
* [Hidden OAuth Attack Vectors (PortSwigger)](https://portswigger.net/research/hidden-oauth-attack-vectors)

---
