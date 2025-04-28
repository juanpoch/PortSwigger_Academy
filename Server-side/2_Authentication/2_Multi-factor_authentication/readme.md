## 🔒 Vulnerabilidades en la Autenticación Multifactor

---

# 🔐 Introducción

La **autenticación multifactor** es una capa adicional de seguridad que exige a los usuarios verificar su identidad utilizando **más de un factor**.

Aunque MFA es más segura que la autenticación de un solo factor, **su efectividad depende totalmente de su correcta implementación**. De lo contrario, puede ser vulnerable a ataques que permiten:

- Bypassear el segundo factor.
- Comprometer ambos factores mediante vectores indirectos.

Esta guía analiza las vulnerabilidades comunes, los tipos de factores utilizados y cómo un atacante podría explotar fallos en MFA.

---

# 🧰 ¿Cómo funciona la autenticación multifactor?

Los factores de autenticación comunes incluyen:

| Tipo de factor | Ejemplo |
|:---------------|:--------|
| Algo que sabes | Contraseña, PIN |
| Algo que tienes | Teléfono móvil, token físico |
| Algo que eres | Huella dactilar, reconocimiento facial |


En la práctica, la forma más frecuente de MFA es la **autenticación de dos factores (2FA)**:

- **Algo que sabes:** Contraseña.
- **Algo que tienes:** Código de verificación generado por un dispositivo externo.


> 🔒 **Importante:** Verificar dos veces "algo que sabes" (por ejemplo, contraseña + código enviado a un correo electrónico) **no** es verdadera autenticación multifactor.


---

# 💥 Vulnerabilidades en la MFA

## 🛡️ Implementaciones defectuosas

Una mala implementación puede permitir eludir la segunda capa de autenticación.

**Ejemplo común:**

- El usuario ingresa la contraseña.
- Luego se le pide el código MFA en una segunda pantalla.
- ❌ Sin embargo, **después de ingresar la contraseña ya se considera "autenticado"**.

**Impacto:**

- El atacante puede acceder directamente a áreas de usuarios registrados sin ingresar el segundo factor.
- Sólo necesita conocer la contraseña de la víctima.



## 🚫 Verificación redundante del mismo factor

**Problema:** Verificar el mismo tipo de factor dos veces.

**Ejemplo:**

- Ingresar contraseña + código recibido por email.
- Ambos factores dependen únicamente del conocimiento (algo que sabes).

**Impacto:**

- Si un atacante compromete el correo electrónico, puede burlar la 2FA.



## 🛋️ Riesgos de los códigos enviados por SMS

Enviar códigos de verificación por SMS puede ser riesgoso:

| Riesgo | Descripción |
|:------|:------------|
| Interceptación | El código viaja por la red de telefonía móvil, donde puede ser interceptado. |
| SIM swapping | El atacante obtiene una copia de la SIM de la víctima y recibe los SMS. |



> 🔒 **Nota:** SMS **verifica algo que tienes**, pero su seguridad depende de la integridad de la red y el dispositivo.

---

# 🛡️ Tokens de Autenticación de Dos Factores

## 🔐 Dispositivos dedicados

Sitios de alta seguridad ofrecen dispositivos específicos:

- **Tokens RSA**
- **Llaves de seguridad (ej: YubiKey)**
- **Aplicaciones de autenticación** (Google Authenticator, Authy)

**Ventajas:**

- Generan los códigos localmente.
- No dependen de redes externas.
- Diseñados específicamente para la seguridad.


## 📱 Aplicaciones móviles dedicadas

Aplicaciones como **Google Authenticator** o **Microsoft Authenticator**:

- Generan códigos TOTP (Time-based One Time Password).
- No requieren conexión a internet.

**Conclusión:** Son alternativas más seguras que los SMS.



---

# 👉 Cómo eludir la autenticación de dos factores

Ataques comunes:

- **Acceso directo a recursos:**
  - Intentar acceder a áreas de usuarios registrados tras solo pasar el primer factor.

- **Interceptar códigos enviados por SMS:**
  - Mediante técnicas de sniffing o ataques de SIM swapping.

- **Omisiones de validación:**
  - Verificar si el sistema no comprueba correctamente si el segundo factor se completó.

**Estrategia de prueba:**

1. Iniciar sesión sólo con contraseña.
2. Intentar navegar hacia una URL protegida.
3. Observar si el sistema permite el acceso sin ingresar el código MFA.


> 🔒 **Recordatorio:** Toda solicitud a recursos sensibles debe validar que el usuario completó **todos** los pasos de autenticación.



---

# 💬 Resumen

| Tema | Riesgo |
|:----|:------|
| Mala implementación de MFA | Permite evadir el segundo factor. |
| Verificación de un solo tipo de factor | Falsa sensación de seguridad. |
| SMS como segundo factor | Vulnerable a interceptación y SIM swapping. |
| Dispositivos dedicados | Mejoran la seguridad notablemente. |


> ✨ **Un MFA efectivo no es sólo agregar pasos: es asegurarse que verifique diferentes factores de manera segura e inequívoca.**

