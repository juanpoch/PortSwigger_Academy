## 🛡️ JWT Attacks&#x20;



### Qué son los JWTs?

Los **JWTs (JSON Web Tokens)** son objetos JSON codificados y firmados criptográficamente que se usan para intercambiar información entre dos partes. Se utilizan principalmente para:

* Autenticación
* Manejo de sesiones
* Control de acceso

Un JWT contiene:

1. **Header**: metadatos del token (algoritmo, tipo)
2. **Payload**: los "claims" (información del usuario)
3. **Signature**: firma digital para verificar integridad y autenticidad

Ejemplo de token:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJ1c2VybmFtZSI6ImNhcmxvcyIsImlzQWRtaW4iOmZhbHNlfQ.
TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```

Puedes decodificar JWTs en [jwt.io](https://jwt.io/) para explorarlos visualmente.

---

### 🔒 ¿Cómo funciona la firma de un JWT?

La firma se genera aplicando una función hash sobre el header y payload, usando una **clave secreta** del servidor:

```
HMAC-SHA256(base64url(header) + "." + base64url(payload), secret)
```

❌ Si un atacante **modifica el payload**, la firma ya no es válida... a menos que la aplicación **no verifique la firma correctamente** o use una clave débil.

---

## ⚡️ Ataques JWT: Conceptos clave

Los ataques a JWTs permiten:

* Suplantar usuarios (cambiar `username`, `sub` o `email`)
* Escalar privilegios (`isAdmin: false → true`)
* Bypass de autenticación sin contraseña

> El impacto suele ser crítico: acceso total a cuentas o paneles administrativos.

---

## 🔧 Vulnerabilidades típicas en JWTs

### 1. **Verificación incorrecta de firma**

Algunos desarrolladores confunden:

* `verify()` ✅: verifica la firma
* `decode()` ❌: solo decodifica el token (sin validar)

Si solo usan `decode()`, cualquier JWT es aceptado, incluso si fue modificado.

**Ejemplo:**

```json
{
  "username": "carlos",
  "isAdmin": true
}
```

El atacante cambia el payload, reconstituye el token, y es aceptado sin validación.

### 2. **Algoritmo ********************`none`******************** en el header**

El header del JWT incluye el campo `alg`:

```json
{ "alg": "HS256", "typ": "JWT" }
```

⚠️ Si el servidor acepta `"alg": "none"`, el atacante puede enviar un token sin firma:

```json
{ "alg": "none" }
```

Token final:

```
base64url(header).base64url(payload).
```

❌ Algunos servidores vulnerables aceptan este token como válido, permitiendo modificar el payload sin restricción.

**Técnicas de evasión**:

* Capitalización mezclada: `NoNe`
* Codificación UTF-8 anormal

### 3. **Uso de claves públicas como si fueran privadas**

Si el servidor cambia el algoritmo de `RS256` (asimétrico) a `HS256` (simétrico), un atacante puede firmar el token con la clave pública obtenida del servidor (usada erróneamente como clave secreta). Este error aparece en implementaciones mal configuradas.

---

## 🤖 Impacto y consecuencias

* Acceso total a cuentas sin credenciales
* Privilegios elevados a usuarios no autorizados
* Compromiso del mecanismo de autenticación

---

## 📃 Trabajando con JWTs en Burp Suite

Burp Suite permite:

* Decodificar JWTs desde la pestaña "Decoder"
* Modificar header, payload y regenerar token
* Automatizar pruebas con extensiones como:

  * [JWT Editor](https://portswigger.net/bappstore/50e2bbf4f38d4c3aa723d7ab6179a5b9)
  * [JWT4B](https://github.com/ticarpi/jwt_tool)

---

---

## 🔎 Recursos recomendados

* [jwt.io - Debugger interactivo](https://jwt.io/)
* [JWT Handbook - Auth0](https://auth0.com/learn/json-web-tokens/)
* [PortSwigger JWT attacks labs](https://portswigger.net/web-security/jwt)
* [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

---

## ✅ Buenas prácticas de seguridad con JWTs

* Nunca confiar en datos del payload sin validar la firma
* Rechazar tokens con `alg: none`
* Usar claves secretas fuertes, rotarlas periódicamente
* Validar correctamente la expiración (`exp`)
* Usar `Authorization Code Flow` con tokens efímeros si es posible

---

> ✨ Entender los JWT y sus fallas comunes es clave para auditar mecanismos de autenticación modernos. La seguridad no está en la codificación, sino en la firma.

---
