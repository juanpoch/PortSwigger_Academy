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

[Lab: Username_enumeration_via_response_timing](3_Username_enumeration_via_response_timing.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)  



---


# Protección contra fuerza bruta con lógica deficiente

La protección contra fuerza bruta busca dificultar la automatización y ralentizar el número de intentos de acceso que puede realizar un atacante. Las dos medidas más comunes son:

* **Bloqueo de cuenta** tras demasiados intentos fallidos.
* **Bloqueo de IP** tras demasiados intentos desde una misma dirección en poco tiempo.

Ambas ofrecen cierto grado de defensa, pero implementaciones con **lógica defectuosa** pueden convertirse en triviales de evadir o en vectores de denegación de servicio contra usuarios legítimos.

---

## Fallas comunes

1. **Reset del contador al haber un éxito en la misma IP**

   * Si el contador de fallos por IP se reinicia cuando la misma IP efectúa un inicio de sesión exitoso en cualquier cuenta (p. ej. el propio atacante), el atacante puede intercalar intentos exitosos para evitar el bloqueo.

2. **Bloqueo por cuenta que permite enumeración**

   * Si la aplicación responde distinto cuando una cuenta es bloqueada (o envía mensajes distintos), permite enumerar usuarios válidos y planear ataques dirigidos.

3. **Bloqueo de IP sin considerar NAT/Proxies**

   * Usuarios legítimos detrás de NAT o proxies compartidos pueden sufrir DoS cuando la IP pública se bloquea.

4. **Timers mal implementados (race conditions)**

   * Contadores distribuidos, sincronización pobre entre servidores o condiciones de carrera pueden permitir múltiples intentos paralelos que el mecanismo no contabiliza correctamente.

5. **Counters globales reiniciables o manipulables**

   * Contadores almacenados en cookies, parámetros client-side o con lógica que permite reset por eventos no autorizados.

6. **Dependencia exclusiva en CAPTCHA visible y fácil de omitir**

   * CAPTCHA mal configurado o servidos desde un endpoint que puede ser evadido.

---

## Ejemplo

**Situación:** la protección bloquea la IP si hay X fallos consecutivos. Pero si desde esa IP se consigue un `login` exitoso en cualquier cuenta, el contador IP se reinicia.

**Bypass sencillo:** intercalar las credenciales de una cuenta legítima (controlada por el atacante) cada N intentos.

**Estrategia:**

* Preparar un `wordlist` con passwords objetivo.
* Insertar la credencial válida del atacante cada (X-1) entradas.
* Automatizar el envío para que tras cada X-1 fallos la IP haga un `login` válido — el contador se reinicia y nunca se llega al umbral.


---

