# Guía: Vulnerabilidades en OAuth 2.0

---

## 🔐 Qué es OAuth 2.0

OAuth 2.0 es un framework de autorización que permite a aplicaciones acceder de forma limitada a datos de usuarios en otras plataformas, **sin exponer las credenciales del usuario**. Es ampliamente utilizado para:

* Autenticación con redes sociales
* Acceso a contactos o información de cuentas de terceros

Aunque fue creado para **autorización**, también se usa como **método de autenticación**, lo que lo vuelve un blanco interesante para atacantes.

---

## 🤷 Actores en el flujo OAuth

1. **Client**: La aplicación que quiere acceder a los datos del usuario.
2. **Resource Owner**: El usuario que posee esos datos.
3. **OAuth Provider**: Plataforma que gestiona la autorización (por ejemplo, Facebook, Google).

---

## ⚖️ Flujos OAuth principales (Grant Types)

### Authorization Code (Servidor)

* Redirige al usuario al proveedor
* El cliente recibe un *authorization code* temporal
* Ese código se intercambia por un *access token*

### Implicit Flow (Cliente)

* El *access token* se entrega directamente en la redirección
* Menos seguro; ya no se recomienda

> ⚠️ Muchas vulnerabilidades surgen por una **implementación incorrecta de estos flujos**

---

## 🔑 OAuth como autenticación

Aunque OAuth no fue diseñado para autenticar usuarios, se utiliza para:

* Iniciar sesión con una cuenta de Google, Facebook, etc.
* Reemplazar el inicio de sesión tradicional con un flujo externo

### Pasos típicos:

1. El usuario elige "Iniciar sesión con..."
2. Se genera un *access token* y se solicita información del usuario (por ejemplo, desde `/userinfo`)
3. Se utiliza esa información para identificar al usuario y autenticarlo

---

## ⚡️ Por qué es vulnerable

* OAuth es complejo, y muchos desarrolladores **implementan flujos personalizados inseguros**
* Algunos ejemplos de fallas:

  * Validación incorrecta del *redirect\_uri*
  * Suplantación de tokens
  * Confianza indebida en parámetros manipulables por el usuario

---

---

## Recursos relacionados

* [OAuth grant types (Web Security Academy)](https://portswigger.net/web-security/oauth/grant-types)
* [Hidden OAuth Attack Vectors (PortSwigger Research)](https://portswigger.net/research/hidden-oauth-attack-vectors)
* [OpenID Connect vulnerabilities](https://portswigger.net/web-security/oauth/openid-connect)

---
