## 🔒 Vulnerabilidades en Otros Mecanismos de Autenticación

---

# 🔐 Introducción

Además de la función de login básico, los sitios web suelen ofrecer funcionalidades complementarias para la **gestión de cuentas**, como:

- Cambio de contraseña.
- Recuperación o restablecimiento de contraseña.
- Funciones de "Recordarme".

Estas funcionalidades **tambien pueden introducir vulnerabilidades** si no se implementan con la misma rigurosidad que el login principal.

**Importante:**

- A menudo se prestan menos atención a estos mecanismos.
- Un atacante que pueda **crear su propia cuenta** podrá estudiar estas funcionalidades en detalle.


---

# 💬 Mecanismo "Recordarme" (Keep Me Logged In)

## 🔒 Descripción

- Al marcar "Recordarme", el servidor genera un **token** persistente.
- Este token se almacena en una **cookie** en el navegador.

**Problema:**

- Si el token es predecible o está mal protegido, puede ser explotado para **bypassar la autenticación**.


## 🛡️ Malas implementaciones comunes:

| Falla | Descripción |
|:------|:------------|
| Tokens predecibles | Basados en concatenaciones de `username + timestamp`, contraseña, o valores estáticos. |
| "Encriptación" trivial | Base64 no es encriptación segura. |
| Hashing inseguro | Si se usa un hash sin salt (como SHA-1 directo), puede ser vulnerable a ataques de fuerza bruta con diccionarios. |



## 🔐 Riesgos adicionales:

- Si un atacante puede crear una cuenta, puede analizar su propio token y **deducir la fórmula** de generación.
- Un **XSS** puede permitir robar tokens de "Recordarme".
- Si la aplicación usa un framework público, la construcción del token podría estar **documentada públicamente**.


## 🔒 Impacto extremo:

- En casos muy inseguros, podría obtenerse directamente **la contraseña en texto claro** desde la cookie o el token.


---



# 🔒 Vulnerabilidades en el Restablecimiento de Contraseña de Usuarios

---

# 🔐 Introducción

En la práctica, es común que los usuarios olviden sus contraseñas. Por lo tanto, los sitios web deben ofrecer un **mecanismo de recuperación de acceso**.

**Problema:**
- Como el usuario no puede autenticarse normalmente, el sistema necesita un **método alternativo** para confirmar su identidad.
- Esta funcionalidad **es crítica y peligrosa** si se implementa mal, ya que podría permitir el secuestro de cuentas.


> ⚡ **El restablecimiento de contraseña es una de las funciones más sensibles en cualquier aplicación web.**


---

# 🔒 Métodos comunes de restablecimiento y sus vulnerabilidades

## 📧 Enviar contraseñas por correo electrónico

### 🔹 Descripción del método

- Algunos sitios envían directamente **la contraseña existente** al correo del usuario.
- Otros generan **una nueva contraseña temporal** y la envían vía email.

### 🔹 Vulnerabilidades y problemas

- **Enviar la contraseña actual:**
  - Implica que las contraseñas están almacenadas en texto plano o reversible.
  - Grave violación de buenas prácticas de almacenamiento seguro (⇒ las contraseñas deberían ser hash con salt).

- **Enviar contraseña nueva por email:**
  - El correo electrónico es un **canal inseguro**:
    - Las bandejas de entrada pueden estar comprometidas.
    - Se sincronizan en múltiples dispositivos no seguros.
    - Pueden ser accedidas por atacantes si no se protegen adecuadamente.
  - Si el usuario **no cambia inmediatamente** esta nueva contraseña, queda expuesto.


### 🔹 Ejemplo de riesgo

1. Usuario solicita restablecer contraseña.
2. El servidor envía "nueva contraseña: `Xyz123!@#`" por correo.
3. El usuario no cambia la contraseña.
4. Un atacante con acceso al email (vía phishing, malware o brecha) puede iniciar sesión con esa contraseña temporal.


---

# 📖 Restablecimiento mediante URL (Token)


## 🔒 Método seguro

- El servidor genera un **token de alta entropía** (un valor largo y aleatorio).
- Envía un enlace al usuario, por ejemplo:

```
https://vulnerable-website.com/reset-password?token=a0ba0d1cb3b63d13822572fcff1a241895d893f659164d4cc550b421ebdd48a8
```

- El sistema:
  - Valida si el token es válido y corresponde a un usuario.
  - Permite que el usuario ingrese una nueva contraseña.
  - **Invalida y destruye** el token una vez usado.



### 🔒 Buenas prácticas esenciales

- El token debe ser **completamente aleatorio y largo** (por ejemplo, 256 bits).
- Debe tener **fecha de expiración corta** (ejemplo: 10-30 minutos).
- Debe ser **de un solo uso** (destruirse después de un solo restablecimiento).
- La URL **no debe revelar ninguna información sobre el usuario**.



### 🛡️ Ejemplo de mala implementación

**URL insegura:**

```
http://vulnerable-website.com/reset-password?user=victim-user
```

- El parámetro `user` es fácilmente manipulable.
- Un atacante puede cambiarlo manualmente (`victim-user` ➞ `admin`) y tratar de restablecer contraseñas de otros usuarios.



### 🛡️ Ataques posibles

- **Token predecible:** Si el token no es suficientemente aleatorio, puede ser adivinado.
- **Token no validado al enviar nueva contraseña:**
  - El servidor permite cambiar la contraseña sin volver a comprobar que el token era correcto.
  - Esto permitiría a un atacante aprovechar su propia sesión y modificar contraseñas de terceros.



### 🔒 Ataque de ejemplo paso a paso

1. El atacante solicita restablecer su propia contraseña.
2. Obtiene la URL segura con su token.
3. Va a la página de restablecimiento de contraseña.
4. **Modifica el parámetro oculto** del formulario para asociarlo a otro usuario.
5. Envía el formulario.
6. Si el servidor **no revalida el token**, se cambia la contraseña de otra cuenta.



---

# 💬 Resumen crítico

| Tema | Riesgo |
|:-----|:------|
| Enviar contraseña por email | Compromiso de confidencialidad, brecha de cuenta. |
| URL insegura con `user` | Hijacking de cuentas mediante manipulación de parámetro. |
| Tokens predecibles o mal manejados | Fuerza bruta o reutilización de enlaces de reset. |
| No revalidar tokens | Permite restablecer contraseñas sin autorización. |



---

# 💎 Mejores Prácticas Recomendadas

- Utilizar **tokens largos, aleatorios e irrepetibles**.
- Hacer que los **tokens expiren rápidamente**.
- **Destruir** el token tras el primer uso.
- **Nunca enviar contraseñas por email**.
- Validar el **token en cada paso**, tanto al cargar la página de cambio como al enviar la nueva contraseña.
- Registrar y alertar sobre restablecimientos sospechosos.


> ✨ **Recordatorio:**
> El mecanismo de "recuperar contraseña" debería ser tan seguro como el propio sistema de login — es una de las mayores puertas de entrada para ataques si no se implementa correctamente.



---

# 💬 Resumen

| Mecanismo | Riesgo |
|:---------|:-------|
| "Recordarme" | Token predecible o robable permite login sin credenciales. |
| Restablecimiento de contraseña | Token débil o falta de validación posterior permite hijacking de cuentas. |
| XSS + "Recordarme" | Permite robar tokens y evitar contraseña. |
| Hashing inseguro | Permite recuperar contraseñas mediante diccionarios conocidos. |



---

> ✨ **En seguridad web, cualquier mecanismo relacionado con autenticación es un objetivo crítico que debe recibir las mismas protecciones que el login principal.**

