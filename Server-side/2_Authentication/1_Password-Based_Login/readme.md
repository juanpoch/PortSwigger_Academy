# Vulnerabilities in password-based login



---

# Introducción

En los sitios web que utilizan **inicio de sesión basado en contraseña**, los usuarios:

- Se registran por sí mismos o
- Reciben una cuenta asignada por un administrador.

Cada cuenta está asociada a:

- Un **nombre de usuario** 
- Una **contraseña secreta**

La **posesión del secreto** se considera suficiente para confirmar la identidad del usuario.

> **Problema:** Si un atacante obtiene o adivina las credenciales, la seguridad del sitio queda comprometida.

---

# Ataques de Fuerza Bruta

## Definición

Un **ataque de fuerza bruta** consiste en:

- Probar masivamente combinaciones de nombres de usuario y contraseñas.
- Automatizar el proceso utilizando **listas de palabras** y **herramientas especializadas**.

Esto permite a un atacante realizar **miles o millones de intentos rápidamente**.

## Lógica y conocimiento humano

No siempre son adivinanzas aleatorias:

- Usan **patrones lógicos**.
- Aprovechan **información pública** (nombres de empleados, convenciones de correo, etc.).

Esto **incrementa la eficiencia** del ataque brutalmente.

**Conclusión:**
- Los sitios que dependen solo de contraseña son altamente vulnerables sin protecciones adecuadas.

---

# Fuerza bruta de nombres de usuario

**Problema:** Los nombres de usuario suelen seguir **patrones predecibles**:

- Correos electrónicos de formato conocido (ej: `nombre.apellido@empresa.com`).
- Usuarios privilegiados comunes (`admin`, `administrator`, `root`).

**Durante auditorías debes verificar:**

- ¿Existen perfiles accesibles públicamente que revelen nombres de usuario?
- ¿Las respuestas HTTP contienen correos de usuarios?

Cualquier pista reduce dramáticamente el esfuerzo del atacante.

---

# Fuerza bruta de contraseñas

**Teóricamente**, las políticas de contraseñas buscan generar contraseñas de **alta entropía**:

- Mínimo de caracteres.
- Mezcla de mayúsculas y minúsculas.
- Inclusión de caracteres especiales.

**En la práctica, los usuarios:**

- Modifican contraseñas predecibles para cumplir la política.
- Ejemplo:
  - De `mypassword` ➞ `Mypassword1!` o `Myp4$$w0rd`.

**Cambio de contraseñas periódicas:**

- Los usuarios tienden a hacer cambios mínimos:
  - `Mypassword1!` ➞ `Mypassword2!`

Esto **facilita enormemente** los ataques basados en patrones de comportamiento humano.

---

# Enumeración de nombres de usuario

**Definición:**

La **enumeración de usernames** ocurre cuando el atacante puede deducir si un nombre de usuario existe observando diferencias en el comportamiento del sitio.

**Puede detectarse en:**

- **Formularios de login:** Respuestas distintas según si el usuario existe.
- **Formularios de registro:** Mensajes como "El usuario ya está en uso".


## Indicadores de enumeración:

| Método | Descripción |
|:-------|:------------|
| Códigos de estado HTTP | Códigos diferentes entre intentos fallidos (ej: 401 vs 403). |
| Mensajes de error | Variaciones pequeñas en los mensajes dependiendo de si el username existe. |
| Tiempos de respuesta | Diferencias sutiles en el procesamiento de peticiones con usuarios existentes. |


**Técnica extra:**

- Introducir contraseñas exageradamente largas.
- Si el tiempo de respuesta se alarga, puede indicar que el username existe (por procesamiento adicional).

---


[Lab: Username enumeration via different responses](1_Username_enumeration_via_different_responses.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)  

[Lab: Username_enumeration_via_subtly_different_responses](2_Username_enumeration_via_subtly_different_responses.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)  

---


