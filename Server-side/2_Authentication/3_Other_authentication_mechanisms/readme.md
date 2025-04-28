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

# 📖 Restablecimiento de Contraseña mediante URL

## 🔒 Método seguro:

- Se genera un **token de alta entropía**.
- El token se envía en una URL privada al usuario:

```
https://vulnerable-website.com/reset-password?token=a0ba0d1cb3b63d13822572fcff1a241895d893f659164d4cc550b421ebdd48a8
```

- El servidor:
  - Valida que el token exista y corresponda al usuario.
  - Asocia la sesión de recuperación al token.
  - Destruye el token después de usarlo.


## 🚫 Malas implementaciones comunes:

| Falla | Descripción |
|:------|:------------|
| Tokens predecibles | URLs como `?user=username` permiten cambiar fácilmente el objetivo. |
| No validación post-envío | El sistema no revalida el token cuando se envía la nueva contraseña. |



## 🛡️ Ataque típico:

1. El atacante solicita restablecer su propia contraseña.
2. Una vez en la página de cambio de contraseña:
   - Elimina manualmente el token en la petición.
   - Intenta cambiar la contraseña de otra cuenta objetivo.
3. Si el servidor no valida el token correctamente, el cambio se realiza.


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

