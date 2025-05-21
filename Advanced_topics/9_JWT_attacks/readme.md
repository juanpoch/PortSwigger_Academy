## 🛡️ JWT Attacks&#x20;



### Qué son los JWTs?

Los **JWTs** son objetos JSON codificados y firmados criptográficamente que se usan para intercambiar información entre dos partes. Se utilizan principalmente para:

* Autenticación
* Manejo de sesiones
* Control de acceso

A diferencia de los tokens de sesión clásicos, todos los datos que necesita un servidor se almacenan en el lado del cliente dentro del propio JWT. Esto convierte a los JWT en una opción popular para sitios web altamente distribuidos donde los usuarios necesitan interactuar fluidamente con múltiples servidores back-end.

## 🔒 JWT: Estructura y relevancia de la firma

Los JWT están compuestos por tres partes codificadas en base64URL y separadas por puntos:

```
HEADER.PAYLOAD.SIGNATURE
```
Ejemplo de token:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJ1c2VybmFtZSI6ImNhcmxvcyIsImlzQWRtaW4iOmZhbHNlfQ.
TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```

### ✉️ Encabezado (Header)

Contiene metadatos sobre el token, como el algoritmo de firma:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

### 📅 Carga úTil (Payload)

Contiene las **claims** o declaraciones del usuario. Ejemplo:

```json
{
  "iss": "portswigger",
  "exp": 1648037164,
  "name": "Carlos Montoya",
  "sub": "carlos",
  "role": "blog_author",
  "email": "carlos@carlos-montoya.net",
  "iat": 1516239022
}
```

Estas claims son información legible por cualquiera que posea el token.

### ✔️ Firma (Signature)

La firma farantiza que el token **no fue modificado** desde que fue emitido. Se genera aplicando una función hash sobre el header y payload, usando una **clave secreta** del servidor:

```
HMAC-SHA256(
  base64url(header) + "." + base64url(payload),
  secret
)
```
En algunos casos, también cifra el hash resultante.  

---

### ⚠️ Riesgo de manipulación

Tanto el header como el payload **son fácilmente decodificables y modificables**, ya que están sólo codificados en base64URL, **no cifrados**.

Por eso:

> ⛔ La seguridad de un JWT **depende totalmente de la verificación correcta de la firma** por parte del servidor.

---

## ⚡️ Ataques JWT: Conceptos clave

Los ataques a JWTs permiten:

* Suplantar usuarios (cambiar `username`, `sub` o `email`)
* Escalar privilegios (`isAdmin: false → true`)
* Bypass de autenticación sin contraseña

> El impacto suele ser crítico: acceso total a cuentas o paneles administrativos.

---

### 🌐 Herramienta recomendada:

Explorá cualquier JWT en [https://jwt.io/](https://jwt.io/) para ver sus tres partes y probar cambios manualmente.


---

## 🔄 JWT vs JWS vs JWE

### 📘 JWT (JSON Web Token)

La especificación JWT es bastante limitada: **define solo un formato estándar** para representar información ("claims") como un objeto JSON estructurado y portable.

Un JWT **por sí solo no implica ni firma ni cifrado**. Simplemente indica cómo deben organizarse los datos:

```json
{
  "sub": "carlos",
  "email": "carlos@ejemplo.com",
  "admin": true
}
```

Pero para que estos datos sean confiables o confidenciales, hay que aplicar otras especificaciones adicionales: **JWS o JWE**.

---

### 🔐 JWS (JSON Web Signature)

* Es la forma **firmada** de un JWT.
* Proporciona **integridad** y **autenticidad** de los datos.
* Usa un algoritmo de firma como HMAC-SHA256 o RS256.

📌 Cuando la gente habla de "JWTs", **casi siempre se refiere a tokens JWS**.

**Ejemplo de estructura JWS:**

```
base64url(header).base64url(payload).base64url(signature)
```

➡️ El contenido se puede leer (está codificado en base64URL), pero **no se puede modificar sin invalidar la firma**.

---

### 🔒 JWE (JSON Web Encryption)

* Es la forma **cifrada** de un JWT.
* Protege la **confidencialidad** del contenido.
* El contenido del token **no puede ser leído** sin la clave privada adecuada.

**Uso típico:** cuando se quiere transmitir datos sensibles y mantenerlos ocultos al cliente o intermediarios.

**Ejemplo de uso:** tokens que contienen datos financieros, historial clínico, etc.

---

### 📝 Nota importante

> Para simplificar, en la mayoría de materiales (y en PortSwigger), el término **"JWT" se refiere a JWS**, salvo que se especifique lo contrario.

No obstante, algunas vulnerabilidades típicas (como el mal uso del campo `alg` o la manipulación de claims) también pueden aplicarse a tokens JWE mal implementados.

---

### 🧠 Resumen

| Tipo | Firma        | Cifrado | Visibilidad del contenido |
| ---- | ------------ | ------- | ------------------------- |
| JWT  | ❌            | ❌       | ✅ legible                 |
| JWS  | ✅            | ❌       | ✅ legible pero protegido  |
| JWE  | ✅ (opcional) | ✅       | ❌ no legible              |

---


## 🔧 Vulnerabilidades típicas en JWTs


## 1. Verificación incorrecta de firma en JWT

Una de las vulnerabilidades más comunes en la implementación de JWT es **no verificar correctamente la firma del token**. Esto suele deberse a un mal uso de las funciones que ofrecen las bibliotecas JWT.

---

### ⚙️ Confusión típica: `decode()` vs `verify()`

Muchas bibliotecas de JWT (como `jsonwebtoken` en Node.js) ofrecen dos funciones clave:

| Método     | ¿Qué hace?                             | ¿Verifica la firma? |
| ---------- | -------------------------------------- | ------------------- |
| `decode()` | Solo decodifica el JWT (base64 → JSON) | ❌ No                |
| `verify()` | Decodifica **y verifica** la firma     | ✅ Sí                |

🔴 **Problema:** Algunos desarrolladores solo usan `decode()`, lo que **omite la validación de la firma**, dejando la aplicación vulnerable.

---

### 🧪 Ejemplo práctico

Supongamos que el servidor espera un JWT como este:

```json
{
  "username": "carlos",
  "isAdmin": false
}
```

El atacante puede:

1. Decodificar el token original (base64url → JSON).
2. Modificar el payload:

```json
{
  "username": "carlos",
  "isAdmin": true
}
```

3. Volver a codificar el header y el payload.
4. Dejar la firma original, o usar cualquier firma falsa.

➡️ Si el backend **no verifica la firma**, aceptará este token como válido y dará acceso administrativo.

---

### 🛠 Herramientas para probar esto

* [jwt.io](https://jwt.io/) permite crear tokens falsos visualmente.
* Extensiones de Burp como **JWT Editor** o **JWT4B** permiten automatizar estos ataques.

---

### 🔐 Consecuencias

* Escalación de privilegios (`isAdmin: false` → `true`)
* Suplantación de identidad (`username: "carlos"`)
* Acceso a funciones restringidas o datos sensibles

---

### ✅ Recomendaciones de defensa

* Usar siempre `verify()` (o su equivalente) en el backend.
* Asegurarse de que se lanza un error si la firma **no es válida o está ausente**.
* Rechazar tokens con errores de estructura o firma, sin excepciones silenciosas.

---

> 📌 **Nunca confíes en el contenido de un JWT si no has verificado su firma.** La codificación base64URL solo oculta, no protege.

[Lab: JWT authentication bypass via unverified signature](1_JWT_authentication_bypass_via_unverified_signature.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

### 2. **Aceptando tokens sin firma**

## ⚠️ Vulnerabilidad por uso del algoritmo `none` en JWT

Una de las vulnerabilidades más conocidas en el uso de JWT es cuando el servidor **acepta tokens sin firma**, específicamente aquellos que declaran en su header:

```json
{
  "alg": "none",
  "typ": "JWT"
}
```

---

### 🧠 ¿Por qué es esto un problema?

El campo `alg` del header de un JWT indica qué algoritmo debe usar el servidor para verificar la firma del token. Si se permite el valor `none`, se está indicando literalmente que **el token no está firmado** y que no requiere validación criptográfica.

Esto implica que un atacante puede:

1. Tomar un JWT válido.
2. Modificar libremente su payload:

```json
{
  "sub": "administrator",
  "role": "admin"
}
```

3. Cambiar el header a:

```json
{
  "alg": "none"
}
```
4. Generar un token con solo dos partes:


`base64url(header).base64url(payload).`


(Sin firma, solo con un punto al final)

👉 Si el servidor acepta este token como válido, entonces el atacante puede autenticarse como cualquier usuario sin conocer ninguna clave secreta.

---

### 🧨 Técnicas de evasión comunes
Incluso si el servidor intenta filtrar `alg=none`, hay formas de evadir el control:

- **Capitalización mezclada**:
  ```json
  { "alg": "NoNe" }
  ```

* **Codificación UTF-8 anormal**:

  * Representar "none" con codificación hexadecimal
  * Inyectar caracteres invisibles o alternativos

Estas técnicas pueden evadir validaciones débiles que solo comparan cadenas exactas y no interpretan correctamente los tipos de codificación.

---

### 🔐 Impacto

* Autenticación sin firma = sin seguridad
* Suplantación de usuarios legítimos
* Acceso no autorizado a recursos protegidos

---

### ✅ Recomendaciones de defensa

* Rechazar explícitamente cualquier token que declare `alg: none`
* Validar los algoritmos permitidos de forma **whitelist** (por ejemplo, solo `HS256`, `RS256`)
* Usar librerías JWT que **ignoren el valor del header `alg` y usen un algoritmo configurado del lado del servidor**

---

> 📌 Esta vulnerabilidad fue explotada en ataques reales como el de Auth0 (2017), y es una de las razones por las que se recomienda evitar confiar en el header del JWT sin controles estrictos.

---

[Lab: JWT authentication bypass via flawed signature verification](2_JWT_authentication_bypass_via_flawed_signature_verification.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

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

  * [Working with JWTs](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/jwts)
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
