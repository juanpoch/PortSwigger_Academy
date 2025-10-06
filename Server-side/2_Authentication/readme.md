## Vulnerabilidades de Autenticación

---

# 🔐 Introducción

Las **vulnerabilidades de autenticación** son conceptualmente sencillas de entender, pero extremadamente críticas debido a su relación directa con la seguridad.

Una falla en los mecanismos de autenticación puede permitir a los atacantes:

- Obtener acceso a datos sensibles.
- Acceder a funcionalidades restringidas.
- Exponer mayor superficie de ataque para realizar futuras explotaciones.

Por eso es fundamental entender cómo se identifican, explotan y previenen estas vulnerabilidades.

---


La **autenticación** es el proceso de **verificar la identidad** de un usuario o cliente.

Dado que los sitios web son accesibles a cualquier persona conectada a Internet, es crucial que sus mecanismos de autenticación sean sólidos para garantizar la seguridad.

### Tipos de factores de autenticación

1. **Algo que sabes** (factor de conocimiento)
   - Ejemplos: contraseña, respuesta a una pregunta de seguridad.

2. **Algo que tienes** (factor de posesión)
   - Ejemplos: teléfono móvil, token de seguridad físico.

3. **Algo que eres o haces** (factor de inherencia)
   - Ejemplos: huella dactilar, reconocimiento facial, patrones de comportamiento.


Los mecanismos de autenticación modernos suelen combinar varios factores para aumentar la seguridad (autenticación multifactor).

---

# Diferencia entre autenticación y autorización

| Concepto | Descripción |
|:---------|:-------------|
| **Autenticación** | Verifica que un usuario es quien dice ser. |
| **Autorización** | Define qué acciones puede realizar el usuario o a qué recursos puede acceder. |

**Ejemplo:**

- **Autenticación:** Confirmar que `Carlos123` realmente es el propietario de esa cuenta.
- **Autorización:** Una vez autenticado, verificar si `Carlos123` puede eliminar cuentas de otros usuarios.

---

# Origen

Existen dos causas principales:

1. **Mecanismos débiles ante ataques de fuerza bruta:**
   - No protegen adecuadamente contra intentos repetidos de adivinanza de contraseña.

2. **Errores de lógica o mala programación:**
   - Permiten evadir completamente el proceso de autenticación.
   - Esto se conoce comúnmente como **Broken Authentication**.

**Nota:**

- En otras áreas de desarrollo, los fallos de lógica podrían ser inofensivos.
- En autenticación, **casi siempre** implican un riesgo grave.

---

# Impacto

Las consecuencias pueden ser devastadoras:

- **Compromiso de cuentas de usuario:**
  - Acceso a toda la información disponible para la cuenta comprometida.

- **Compromiso de cuentas privilegiadas:**
  - Control total sobre la aplicación.
  - Acceso potencial a la infraestructura interna.

- **Acceso a información sensible de negocio:**
  - Incluso cuentas de bajo privilegio podrían revelar datos importantes.

- **Superficie de ataque expandida:**
  - Desde una página interna, un atacante puede explotar nuevas vulnerabilidades no disponibles públicamente.


---

# 🔒 Mecanismos de autenticación vulnerables

Una aplicación suele implementar varios mecanismos donde pueden presentarse vulnerabilidades:

- **Inicio de sesión con contraseña**
- **Autenticación multifactor (MFA)**
- **Otros mecanismos personalizados**
- **Autenticación de terceros (OAuth, SSO)**

Cada uno tiene su propio conjunto de riesgos.

---

# 🛡️ Vulnerabilidades en autenticación de terceros

Cuando un sitio depende de servicios externos (por ejemplo, **OAuth**):

- Un error en la implementación puede permitir eludir la autenticación.
- Los laboratorios de OAuth están diseñados para aprender a encontrar y explotar estos errores.

---

# Prevención de vulnerabilidades en mecanismos de autenticación

Al diseñar sistemas de autenticación seguros, es fundamental seguir algunos principios clave:

- **Proteger contra fuerza bruta:**
  - Implementar límites de intentos fallidos.
  - Uso de captchas.
  - Introducir retardos exponenciales.

- **Validar correctamente todas las entradas.**

- **Utilizar almacenamiento seguro de contraseñas:**
  - Algoritmos de hashing robustos.

- **Integrar MFA correctamente.**

- **Aplicar el principio de menor privilegio:**
  - Las cuentas deberían tener solo los permisos estrictamente necesarios.

- **Utilizar bibliotecas y estándares comprobados en lugar de desarrollar mecanismos propios inseguros.**

- **Auditar y probar regularmente los sistemas de autenticación.**

---

---



La autenticación es un tema complejo y propenso a errores. Aunque no es posible cubrir absolutamente todas las medidas de protección posibles, existen principios generales que **siempre** deberías seguir para robustecer tus sistemas de autenticación.

En esta guía aprenderás cómo prevenir las vulnerabilidades comunes y fortalecer tu autenticación.

---

# Cuidar las credenciales de los usuarios

Incluso los mejores sistemas de autenticación son inútiles si un atacante obtiene las credenciales:

- **Nunca envíes datos de inicio de sesión por conexiones no cifradas**.
- **Implementa HTTPS** en todas las páginas, no solo en el login.
- **Redirige automáticamente HTTP a HTTPS**.
- **Audita el sitio** para asegurarte de que:
  - No se filtren nombres de usuario o correos electrónicos en perfiles o respuestas HTTP.

---

#  No depender de los usuarios para la seguridad

La naturaleza humana tiende a buscar atajos. Por eso debes **forzar comportamientos seguros**.

### Implementar una buena política de contraseñas

- **Evita políticas tradicionales** (longitud mínima con complejidad obligatoria) que los usuarios terminan sorteando con contraseñas predecibles.
- **Usa un verificador de fortaleza de contraseñas en tiempo real**, como:
  - [zxcvbn](https://github.com/dropbox/zxcvbn) de Dropbox.
- **Obliga a aceptar solo contraseñas calificadas como "fuertes"**.

---

# Prever la enumeración de nombres de usuario

Facilitar la detección de usuarios existentes ayuda a los atacantes.

Recomendaciones:

- **Usa mensajes de error genéricos e idénticos** sin importar si el usuario existe o no.
- **Devuelve siempre el mismo código de estado HTTP**.
- **Normaliza el tiempo de respuesta** para hacer los intentos indistinguibles.

---

# Implementar protección robusta contra fuerza bruta

Dado lo simple que es lanzar ataques de fuerza bruta, debes complicar al máximo los intentos:

- **Limita el número de intentos por IP**.
- **Evita manipulaciones del IP aparente**.
- **Usa CAPTCHA** tras superar un umbral de intentos fallidos.

Nota: aunque no elimina el riesgo por completo, **aumenta el esfuerzo y desalienta** a atacantes oportunistas.

---

# Verificar la lógica de validación una y otra vez

- **Audita a fondo** toda la lógica de verificación.
- **Evita errores de programación o de lógica** que puedan ser explotados.
- **Una verificación que puede ser evadida equivale a no tener verificación**.

---

# No olvidar las funcionalidades complementarias

No te centres solo en el login principal.

Debes proteger también:

- **Mecanismos de registro de usuarios**.
- **Restablecimiento y cambio de contraseña**.
- **Recuperación de cuentas**.

Cada uno representa una posible superficie de ataque.

Especialmente crítico si el atacante puede registrar su propia cuenta para explorar.

---

# Implementar correctamente la autenticación multifactor (MFA)

Cuando se aplica adecuadamente, MFA mejora sustancialmente la seguridad.

- **No verifiques múltiples instancias del mismo factor** (por ejemplo, contraseña + código enviado por email ≠ verdadero MFA).
- **SMS como segundo factor**:
  - Aunque técnicamente es un segundo factor, puede ser vulnerable (por ejemplo, ataque de SIM swapping).

### Mejor práctica recomendada:

- Usar **aplicaciones dedicadas** de generación de códigos, como:
  - Google Authenticator.
  - Authy.
  - Dispositivos de autenticación físicos (YubiKey, etc).

- **Auditar también la lógica del MFA** para asegurar que no pueda ser evadida.

---

# 💬 Resumen

| Principio | Acción recomendada |
|:----------|:-------------------|
| Proteger credenciales | HTTPS obligatorio, no filtrar usuarios. |
| Forzar comportamientos seguros | Uso de password checkers en tiempo real. |
| Evitar enumeración | Mensajes y tiempos de respuesta uniformes. |
| Dificultar fuerza bruta | Rate limiting + CAPTCHA. |
| Verificar la lógica | Auditorías profundas de toda validación. |
| Asegurar todo el ecosistema | Incluir registro, recuperación de contraseña, MFA. |

---

> **La autenticación robusta no es solo un login seguro; es proteger toda la superficie que permite controlar identidades.**



