## 🧠 Access control vulnerabilities and privilege escalation

En esta sección vamos a explicar en profundidad qué son los controles de acceso, por qué son importantes, cuáles son los modelos más comunes, qué formas toma su ruptura (broken access control), y cómo se puede prevenir este tipo de vulnerabilidad tan crítica.

---

### 🔐 ¿Qué es el control de acceso?

El control de acceso es el conjunto de mecanismos que definen qué usuarios pueden realizar determinadas acciones o acceder a ciertos recursos. En aplicaciones web, el control de acceso está fuertemente vinculado a:

- **Autenticación**: verifica la identidad del usuario.
- **Gestión de sesiones**: mantiene esa identidad durante las peticiones HTTP subsecuentes.
- **Control de acceso**: impone las restricciones sobre lo que el usuario autenticado puede hacer.

Una mala implementación de controles de acceso es una de las vulnerabilidades más comunes y críticas en el desarrollo de software.

---

# 🔖 Modelos de Seguridad de Control de Acceso

Los modelos de seguridad de control de acceso definen formalmente las reglas mediante las cuales los sistemas determinan si un sujeto (por ejemplo, un usuario) puede acceder a un objeto (por ejemplo, un recurso, archivo o funcionalidad). Elegir el modelo adecuado es clave para implementar políticas de seguridad que equilibren protección, eficiencia y facilidad de gestión.

---

## ✅ Programmatic Access Control
Este modelo no depende de una estructura fija como los roles o grupos, sino que define una **matriz de privilegios** almacenada normalmente en una base de datos. El sistema consulta esta matriz en tiempo real para validar si un usuario puede ejecutar determinada acción sobre un recurso.

### ✨ Ventajas:
- Altamente granular.
- Flexible y personalizable.
- Permite implementar reglas específicas para contextos complejos (por ejemplo: restricciones por horario, ubicación, estado de un proceso, etc.).

### 📆 Ejemplo:
```sql
-- Tabla de privilegios
user_id | recurso     | accion     | permitido
--------|-------------|------------|-----------
1       | /admin      | DELETE     | true
2       | /admin      | DELETE     | false
```
El backend consulta esta matriz antes de ejecutar la acción solicitada.

---

## ✉️ Discretionary Access Control (DAC - Control de Acceso Discrecional)
En este modelo, el **dueño del recurso** tiene la potestad de decidir quién puede acceder a él y en qué medida.

### ✨ Ventajas:
- Muy flexible para entornos colaborativos.
- Fácil de entender.

### ⚠️ Riesgos:
- Difícil de escalar en sistemas grandes.
- Los usuarios pueden cometer errores y otorgar permisos excesivos.

### 📆 Ejemplo:
Un usuario crea un archivo y comparte acceso de lectura con otro usuario. Si se equivoca y da acceso de escritura, podría causar una brecha.

---

## 🏛️ Mandatory Access Control (MAC - Control de Acceso Obligatorio)
Modelo estricto y centralizado. Los usuarios no pueden modificar los permisos. El sistema define reglas globales y etiquetas de seguridad.

### 🔒 Claves del modelo:
- Cada objeto tiene una clasificación (por ejemplo: Confidencial, Secreto, Top Secret).
- Cada sujeto tiene un nivel de autorización.
- El acceso solo se permite si la autorización del sujeto es igual o superior a la clasificación del objeto.

### ✨ Usos comunes:
- Entornos militares o gubernamentales.
- Sistemas que requieren cumplimiento estricto de confidencialidad.

### 📆 Ejemplo:
Un empleado con nivel "Secreto" no podrá acceder a documentos "Top Secret", pero sí a documentos "Confidencial" o "Público".

---

## 📂 Role-Based Access Control (RBAC - Control de Acceso Basado en Roles)
Modelo ampliamente utilizado en entornos empresariales. Se crean **roles** (conjuntos de permisos) y los usuarios son asignados a uno o más roles.

### 📄 Ejemplo de roles:
- `Admin`: Puede gestionar usuarios, editar contenido y ver reportes.
- `Editor`: Puede crear y editar contenido.
- `Viewer`: Solo puede leer contenido.

### ✨ Ventajas:
- Escalable y fácil de administrar.
- Se adapta bien a organizaciones estructuradas por funciones.
- Reduce el riesgo de errores humanos en la asignación de permisos.

### ⚠️ Consideraciones:
- Definir demasiados roles puede hacer que el sistema sea complejo de mantener.

---

## 🔹 Conclusión
Cada modelo tiene sus ventajas y desventajas. En la práctica, muchas aplicaciones modernas utilizan combinaciones de estos enfoques, como RBAC complementado con controles programáticos y lógicas adicionales para ciertos casos especiales.

La clave está en seleccionar el modelo (o combinación) que mejor se adapte a los requisitos de seguridad, escalabilidad y mantenibilidad de la organización.

---

### 🌐 Tipos de controles de acceso

#### ↕️ **Vertical Access Control**
Restringe funcionalidades según el tipo de usuario:

- Un usuario normal no puede acceder al panel de administrador.
- Un moderador puede editar comentarios pero no eliminar usuarios.

#### 🛋 **Horizontal Access Control**
Restringe recursos entre usuarios del mismo tipo:

- Un usuario puede acceder sólo a su perfil: `/user/juan` y no al de `/user/maria`.
- Una app bancaria permite ver solo tus transacciones, no las de otros.

#### ⌛ **Context-Dependent Access Control**
Restringe acciones según el estado de la aplicación:

- No puedes modificar el carrito de compras después de pagar.
- No se puede saltar pasos en un flujo de onboarding.

---

### ❌ Ejemplos de Broken Access Control

#### ⬆️ **Vertical Privilege Escalation**
Un usuario normal accede a funciones administrativas:

```http
GET /admin/deleteUser?username=carlos
```

Si la app no verifica que el usuario tiene privilegios, puede ejecutar esta acción.

#### 🔒 **Funcionalidad sin protección**
Si una página administrativa existe pero no está protegida:

- No hay verificación de roles.
- Está accesible por URL directa.

Ejemplo:
```
https://vulnerable-site.com/admin
```

Incluso si no hay enlaces visibles, el atacante podría descubrir esta ruta por:
- `robots.txt`
- Wordlists + fuerza bruta con Burp Suite, Dirbuster, ffuf, etc.

#### 🛎 **Horizontal Privilege Escalation**
Un usuario accede a los recursos de otro cambiando un ID:

```http
GET /account/details?user_id=112  --> Cambiar por 113
```

Si el backend no verifica que el usuario autenticado es el dueño de `user_id`, puede acceder a información ajena.



[Lab: Unprotected admin functionality](1_Unprotected_admin_functionality.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

## 🔒 Seguridad por oscuridad y su ineficacia como control de acceso

En algunos entornos web, los desarrolladores optan por **ocultar funciones sensibles** asignándoles URLs ofuscadas o poco predecibles. Esta práctica se conoce como **seguridad por oscuridad (security through obscurity)**. Si bien puede parecer una capa de protección adicional, **no constituye un mecanismo de control de acceso efectivo**.

### 🧩 ¿Qué es seguridad por oscuridad?
Seguridad por oscuridad es una estrategia que intenta mantener ciertos componentes del sistema seguros **al ocultarlos** o **dificultar su descubrimiento**. En lugar de proteger un recurso mediante autenticación, roles o restricciones, se basa en que un atacante no adivine su existencia.

> **Ejemplo:**
>
> Una aplicación podría alojar su panel de administración en una URL no obvia, como:
>
> `https://insecure-website.com/administrator-panel-yb556`
>
> La idea detrás de esta práctica es que un atacante no podrá descubrir esa URL a menos que la adivine o sea filtrada por otro medio.

### ⚠️ ¿Por qué no es seguro?
Aunque usar una ruta no estándar puede **dificultar brevemente el descubrimiento**, **no impide el acceso** si alguien logra identificarla. Esta protección es fácilmente evitable con técnicas como:

- Content discovery con herramientas como **Gobuster**, **FFUF**, **Dirb**, etc.
- Revisión de archivos como `robots.txt` o `sitemap.xml`.
- Fugas en comentarios HTML o archivos JavaScript.
- Ingeniería inversa del código fuente del frontend.

> **Ejemplo concreto:**
>
> El siguiente fragmento de JavaScript pertenece a la interfaz de usuario:
>
> ```html
> <script>
> 	var isAdmin = false;
> 	if (isAdmin) {
> 		...
> 		var adminPanelTag = document.createElement('a');
> 		adminPanelTag.setAttribute('href', 'https://insecure-website.com/administrator-panel-yb556');
> 		adminPanelTag.innerText = 'Admin panel';
> 		...
> 	}
> </script>
> ```
>
> Aunque el botón del panel de administración sólo se renderiza si `isAdmin` es `true`, **el código completo es visible para todos los usuarios**, incluyendo la URL ofuscada. Un atacante que inspeccione el JavaScript puede acceder manualmente al panel simplemente copiando la URL.

### 🛡️ ¿Cuál es la alternativa correcta?
Para proteger funciones sensibles como un panel de administración, **es necesario implementar controles de acceso reales**, por ejemplo:

- Requerir autenticación válida.
- Verificar el rol del usuario en cada solicitud del backend.
- Restringir las funciones según principios como **mínimo privilegio** o **separación de funciones**.

### ✅ Buenas prácticas
- No confíes en la ofuscación como único mecanismo de seguridad.
- Toda función sensible debe validar explícitamente que el usuario tiene permiso para acceder.
- Realizá pruebas de enumeración de rutas y análisis de código en busca de fugas de URLs sensibles.
- Usá cabeceras como `X-Robots-Tag: noindex` y bloqueos adecuados en `robots.txt`, pero **no como única protección**.

### 🧠 Conclusión
Ocultar recursos es una medida complementaria, **nunca un reemplazo del control de acceso**. En un entorno de seguridad serio, debemos asumir que un atacante puede encontrar cualquier URL. El objetivo no es ocultarlas, sino asegurarse de que **no pueda usarlas sin autorización**.

[Lab: Unprotected admin functionality with unpredictable URL](2_Unprotected_admin_functionality_with_unpredictable_URL.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

## Métodos de control de acceso basados en parámetros

Uno de los errores más frecuentes en la implementación de mecanismos de autorización en aplicaciones web es el uso de **parámetros controlados por el usuario** para decidir el nivel de acceso o privilegio que se le otorga al mismo. Este enfoque es **intrínsecamente inseguro**, ya que permite al atacante modificar esos valores y potencialmente escalar privilegios o acceder a funcionalidades restringidas.

---

### 🔍 ¿En qué consiste?

En este patrón inseguro, la aplicación determina el rol o los derechos del usuario al momento del login y almacena esa información en un lugar que **puede ser manipulado por el cliente**, como por ejemplo:

- Un **campo oculto** (`<input type="hidden">`).
- Una **cookie**.
- Un **parámetro en la URL** (query string).

Luego, al navegar por la aplicación, se toman decisiones de acceso **en base a ese valor enviado por el cliente**, en lugar de verificar en el backend el rol real del usuario autenticado.

---

### 🧪 Ejemplos comunes

Imaginemos una aplicación que, luego de hacer login, redirige a la siguiente URL:

```
https://insecure-website.com/login/home.jsp?admin=false
```

En este caso, el sistema podría usar ese parámetro `admin` para mostrar u ocultar funcionalidades administrativas. Si el usuario malicioso simplemente cambia la URL a:

```
https://insecure-website.com/login/home.jsp?admin=true
```

...podría acceder al panel de administración si no hay validación en el servidor.

Otro ejemplo común:

```
https://insecure-website.com/dashboard.jsp?role=1
```
Donde `role=0` representa un usuario común y `role=1` representa un administrador.

Modificando ese parámetro en la URL, el atacante podría simular pertenecer a un rol más privilegiado y acceder a funcionalidades restringidas.

---

### ⚠️ ¿Por qué es una mala práctica?

Este patrón viola un principio fundamental de la seguridad: **el control de acceso debe validarse exclusivamente del lado servidor**. Cualquier dato que se envíe desde el cliente debe considerarse potencialmente manipulado y no debe utilizarse como fuente de verdad.

Confiar en valores enviados por el cliente permite a un atacante:
- Realizar **elevación vertical de privilegios** (por ejemplo, de usuario a administrador).
- Acceder a funciones administrativas o sensibles sin autorización.
- Eludir lógicas de negocio importantes (por ejemplo, realizar acciones en nombre de otro usuario).

---

### 🔐 Buenas prácticas para evitar este problema

- **Nunca confiar en datos del cliente** para tomar decisiones de seguridad.
- Utilizar **mecanismos del lado servidor** para asociar la sesión del usuario a su rol o privilegios reales.
- Almacenar el rol del usuario en el **backend** (por ejemplo, en la base de datos o en la sesión) y verificarlo en cada solicitud crítica.
- Evitar exponer datos sensibles o determinantes en cookies sin mecanismos de protección (por ejemplo, HMAC).

---

### 🛠️ Ejemplo seguro

En vez de depender de la URL o de un campo oculto, una buena práctica sería:

1. Al autenticarse, el servidor consulta el rol del usuario desde la base de datos.
2. El rol se almacena **del lado servidor** en la sesión.
3. En cada acceso a rutas sensibles, el backend valida:

```python
if session["user_role"] != "admin":
    return redirect("/unauthorized")
```

Así se garantiza que el usuario no puede modificar su rol desde el cliente.

---

### 🧠 Reflexión final

Este tipo de errores es fácil de cometer y puede parecer funcional en etapas tempranas de desarrollo. Sin embargo, abre la puerta a accesos no autorizados, escaladas de privilegios y exposición de funcionalidades críticas. Cualquier auditoría de seguridad o prueba de penetración debe incluir la búsqueda activa de este patrón, sobre todo si se observan parámetros sospechosos como `admin=true`, `role=1`, `accessLevel=3`, etc.

En resumen: **los parámetros del cliente no son confiables para aplicar control de acceso**. Siempre validar del lado servidor.

[Lab: User role controlled by request parameter](3_User_role_controlled_by_request_parameter.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 


[Lab: User role can be modified in user profile](4_User_role_can_be_modified_in_user_profile.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 


---

## 🔒 Broken Access Control from Platform Misconfiguration y Coincidencias de URL

### ⚠️ Fallos en controles de acceso a nivel de plataforma

Muchas aplicaciones modernas delegan parte del control de acceso al nivel de la plataforma (por ejemplo, configuraciones de web servers o frameworks), usando reglas del tipo:

```
DENY: POST, /admin/deleteUser, managers
```

Esta regla prohibiría que los usuarios con el rol "manager" realicen peticiones `POST` al endpoint `/admin/deleteUser`. Sin embargo, esto puede romperse debido a configuraciones erróneas o comportamientos especiales del servidor.

#### 🔎 Bypass con headers no estándar
Muchos frameworks y servidores admiten headers HTTP especiales como `X-Original-URL`, `X-Rewrite-URL` o `X-Forwarded-Prefix`. Estos pueden ser utilizados por proxies inversos o configuraciones internas para reescribir rutas.

**Ejemplo de exploit:**
```http
POST / HTTP/1.1
Host: vulnerable.com
X-Original-URL: /admin/deleteUser
...
```

Aunque la URL sea `/`, el servidor podría usar el valor de `X-Original-URL` para enrutar la petición internamente. Si la plataforma no valida el header correctamente, el control de acceso puede ser saltado.

#### 🔀 Cambios en el método HTTP
Si los controles de acceso sólo están definidos para ciertos métodos, como `POST`, pero el backend también acepta `GET`, `PUT` u otros para el mismo recurso, un atacante puede cambiar el verbo HTTP:

**Ejemplo:**
```http
GET /admin/deleteUser HTTP/1.1
```
Esto podría ejecutar la misma acción que el `POST` si el backend no restringe el método.

---

### 🔗 Desajustes en coincidencias de URL

Algunos controles de acceso pueden depender de coincidencias estrictas de ruta, pero otros componentes pueden tener reglas más relajadas.

#### 1. Mayúsculas y minúsculas:
Un servidor puede permitir acceder a `/ADMIN/DELETEUSER` aunque el path definido sea `/admin/deleteUser`. Si el sistema de control de acceso distingue mayúsculas y minúsculas, podría fallar:

```
Acceso real: /ADMIN/DELETEUSER ✔
Controles aplicados a: /admin/deleteUser ❌
```

#### 2. Sufijos (Spring `useSuffixPatternMatch`)
En versiones anteriores de Spring (pre 5.3), la opción `useSuffixPatternMatch=true` está habilitada por defecto. Esto permite acceder a:
```
/admin/deleteUser.json
/admin/deleteUser.anything
```
Que serán tratados como `/admin/deleteUser`. Si el sistema de control de acceso sólo protege la versión exacta, se puede omitir.

#### 3. Slash final opcional
Algunos frameworks tratan `/admin/deleteUser` y `/admin/deleteUser/` como rutas diferentes. Si los controles de acceso sólo aplican a una, podría omitirse agregando o quitando la barra final.

---

### 🤹 Horizontal Privilege Escalation

Este tipo de escalada ocurre cuando un usuario puede acceder a recursos de otros usuarios del mismo nivel.

**Ejemplo:**
```
Usuario accede a su cuenta:
https://insecure-website.com/myaccount?id=123
```
Un atacante cambia:
```
?id=124
```
Y accede al perfil de otro usuario.

Este es un caso clásico de:
> 📄 **IDOR (Insecure Direct Object Reference)**

Los IDOR ocurren cuando valores controlados por el usuario acceden directamente a objetos sin validación adecuada.

---

### ✅ Recomendaciones
- Validar todos los headers utilizados para enrutar peticiones, incluyendo los no estándares.
- Restringir los métodos HTTP permitidos a nivel de servidor (p.ej., bloquear TRACE, PUT si no se usan).
- Usar coincidencias estrictas y unificadas de URL.
- Desactivar `useSuffixPatternMatch` en Spring si no es necesario.
- Nunca confiar en identificadores controlados por el cliente para el acceso a recursos. Validar en base a la sesión del usuario autenticado.

[Lab: User ID controlled by request parameter](5_User_ID_controlled_by_request_parameter.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)

---

## 🔐 IDOR con Identificadores No Predecibles (GUIDs)

### 🧠 Contexto
Cuando una aplicación usa identificadores secuenciales o predecibles (por ejemplo: `id=1`, `id=2`, etc.), es fácil para un atacante adivinar otros valores y realizar ataques de tipo **IDOR** (Insecure Direct Object Reference), accediendo a recursos ajenos.

Para mitigar esto, muchas aplicaciones modernas utilizan **GUIDs** (Globally Unique Identifiers), que son valores largos y difíciles de predecir, por ejemplo:
```
9a32db79-91f2-4a57-a8ef-134e4d3218ff
```

Esto dificulta (pero **no previene**) los ataques IDOR.

---

### ⚠️ ¿Dónde está el problema?
Aunque los GUIDs no sean predecibles, pueden **filtrarse de otras maneras**. Muchas veces, otros endpoints o secciones del sitio exponen información relacionada a usuarios o recursos, incluyendo estos identificadores únicos.

#### 🔍 Ejemplo práctico:

Una aplicación muestra reseñas de productos con identificadores de usuario:

```json
[
  {
    "user": {
      "name": "Carlos",
      "id": "c90ec581-760a-4f14-996a-d7c6f67ef9a5"
    },
    "review": "Muy buen producto!"
  }
]
```

Un atacante puede:

1. **Recolectar GUIDs** observando este tipo de respuestas (por ejemplo, usando un proxy como Burp).
2. Usar estos GUIDs en otros endpoints, por ejemplo:

```
GET /api/users/c90ec581-760a-4f14-996a-d7c6f67ef9a5/profile
```

3. Si no hay un control de acceso efectivo, podría visualizar (o modificar) los datos del usuario Carlos.

---

### 💪 Técnicas comunes para explotar estos escenarios

- Revisar JSON, HTML o comentarios en páginas que muestren IDs de usuario.
- Analizar endpoints que retornen múltiples objetos (ej. `/reviews`, `/posts`, `/comments`).
- Observar parámetros `userId`, `accountId`, `client_id`, `guid`, etc. en URLs, cuerpo de la petición, headers o respuestas.
- Automatizar la búsqueda con Burp Suite + Logger++, o con scripts personalizados.

---

### 🛡️ ¿Cómo prevenir esto?

- **Implementar controles de acceso a nivel de backend.** No confiar jamás en que un identificador poco predecible es suficiente.
- **Evitar exponer GUIDs innecesariamente**. Mostrar solo los datos requeridos para el usuario.
- **Usar Access Control Lists (ACLs)** o lógica robusta en el backend que valide si el usuario realmente está autorizado a acceder al recurso referenciado.

---

### 📚 Resumen

| Riesgo | Falsa sensación de seguridad por usar GUIDs |
|--------|----------------------------------------------|
| Error | Suponer que lo impredecible = seguro          |
| Realidad | Los GUIDs pueden ser expuestos indirectamente |
| Prevención | Autorización robusta en el backend        |


[Lab: User ID controlled by request parameter with unpredictable user IDs](6_User_ID_controlled_by_request_paramete_with_unpredictable_user_IDs.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)

---

### 🔐 Filtración de información sensible en respuestas con redirección

En algunos casos, una aplicación *sí detecta* que el usuario actual no tiene permiso para acceder a cierto recurso, y responde con una **redirección al login** (por ejemplo, con un código HTTP `302 Found` o `303 See Other`). A primera vista, esto parece una implementación adecuada de control de acceso, ya que evita el acceso completo al recurso restringido.

**Sin embargo, puede haber un fallo crítico**:  
📦 **La respuesta HTTP que contiene la redirección también puede incluir información sensible del recurso solicitado.**

---

### 🧠 ¿Cómo puede ocurrir esto?

Veamos un ejemplo realista. Imaginá que un usuario autenticado con ID `1002` intenta acceder a los datos de un usuario diferente (ID `1001`), accediendo a la siguiente URL:

```
GET /user/account?id=1001 HTTP/1.1
Cookie: session=eyJh...
```

La aplicación detecta correctamente que el usuario no tiene permiso, y devuelve:

```http
HTTP/1.1 302 Found
Location: /login
```

Pero **en el cuerpo de la respuesta**, por un error del backend, incluye algo como:

```html
<!-- User email: carlos@example.com -->
<!-- User address: 123 Admin Street -->
```

---

### 🛠 ¿Por qué ocurre esto?

Esto suele suceder por fallos de lógica en el backend. Algunas causas comunes:

- La aplicación **procesa y recupera la información del recurso** antes de verificar si el usuario tiene permiso.
- El servidor genera el contenido de la respuesta **y luego decide** que el usuario no puede verlo, pero **no limpia adecuadamente** el cuerpo de la respuesta.
- Algunos frameworks **agregan metadatos o trazas** en la redirección por defecto, exponiendo valores que deberían permanecer privados.

---

### 📌 ¿Qué tipo de datos podrían filtrarse?

- Correos electrónicos de otros usuarios
- Direcciones físicas
- Tokens de acceso o identificadores internos
- Rutas privadas o nombres de archivo
- Fragmentos de datos HTML sensibles (por ejemplo, valores pre-cargados en formularios)

---

### ✅ Recomendaciones para evitar esta vulnerabilidad

- **Verificar permisos antes de cargar datos.** El backend debe rechazar el acceso *antes* de interactuar con el recurso.
- **Sanitizar completamente las respuestas de redirección.** Nunca incluir datos sensibles si se va a redirigir al usuario.
- **Auditar las rutas protegidas** usando herramientas de pentesting automatizadas y manuales para detectar este patrón.
- Implementar pruebas de seguridad (unitarias o funcionales) que validen que las redirecciones no contienen contenido no autorizado.

[Lab: User ID controlled by request parameter with data leakage in redirect](7_User_ID_controlled_by_request_parameter_with_data_leakage_in_redirect.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)


---

## 🔗 Horizontal to Vertical Privilege Escalation

Una **escalada de privilegios horizontal** ocurre cuando un usuario accede a recursos de otros usuarios con el mismo nivel de privilegios. En cambio, una **escalada vertical** implica que un usuario con menos privilegios accede a funcionalidades reservadas para usuarios con roles superiores (como administradores).

### ⚠️ De horizontal a vertical: el puente
En algunas situaciones, una vulnerabilidad de tipo horizontal puede utilizarse como trampolín para escalar verticalmente. Este escenario se da cuando:

- El atacante puede acceder a los recursos de otro usuario.
- El usuario objetivo tiene más privilegios (por ejemplo, es un administrador).

#### 🔎 Ejemplo práctico:
Un atacante identificado como `user1` accede a su propio perfil mediante:
```
GET /myaccount?id=123
```
Mediante manipulación de parámetro, intenta acceder al perfil del usuario `456`:
```
GET /myaccount?id=456
```
Si `456` corresponde a un administrador y la aplicación no valida correctamente el acceso, el atacante ahora está viendo el perfil de un usuario con mayores privilegios.

### 🔒 Posibilidades de explotación:
Una vez dentro del perfil del administrador, el atacante podría:

- **Ver y editar la contraseña del administrador**: si hay formularios de actualización accesibles.
- **Leer información sensible**: como usuarios registrados, configuraciones, logs, etc.
- **Acceder a funcionalidades privilegiadas**: como paneles de administración.

#### 🔐 Escenario típico en aplicaciones vulnerables:
- Los usuarios son identificados por ID en parámetros GET o POST (`id=456`).
- No hay verificación del lado del servidor que compruebe si el usuario autenticado tiene permiso para consultar ese recurso.
- Los administradores acceden al mismo endpoint que los usuarios, pero con más funcionalidades visibles.

### ❌ Consecuencias:
- Pérdida de control sobre funciones administrativas.
- Exposición total de datos sensibles.
- Compromiso del sistema si el atacante gana persistencia desde una cuenta de administrador.

### 🔧 Recomendaciones de mitigación:
- ✅ **Implementar controles de acceso basados en el contexto de usuario autenticado**: El backend debe validar que el usuario autenticado tiene acceso al recurso solicitado, no confiar en valores de parámetro (`id`, `username`, etc.).
- ✅ **Evitar la exposición de funciones privilegiadas en interfaces compartidas**.
- ✅ **Registrar y auditar accesos sospechosos**, como peticiones donde un usuario accede a un recurso que no le corresponde.

### 📊 Conclusión:
Una vulnerabilidad de **IDOR** (Insecure Direct Object Reference) que permite acceso horizontal puede convertirse en una amenaza crítica si el atacante la utiliza para comprometer a un usuario con privilegios superiores. Por eso, es esencial implementar controles de acceso estrictos tanto a nivel horizontal como vertical.

[Lab: User ID controlled by request parameter with password disclosure](8_User_ID_controlled_by_request_parameter_with_password_disclosure.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)

---

## 🧩 Insecure Direct Object References (IDOR)

Los IDOR (Insecure Direct Object References) son una subcategoría de las vulnerabilidades de control de acceso. Se producen cuando una aplicación utiliza directamente entradas proporcionadas por el usuario para acceder a recursos u objetos internos, sin realizar una validación adecuada sobre si el usuario tiene autorización para interactuar con dichos recursos.

Esta vulnerabilidad fue formalmente reconocida como parte del OWASP Top 10 en 2007, lo que contribuyó a su popularidad en el campo de la seguridad web. Aunque no todas las fallas de acceso directo son IDOR, esta categoría describe uno de los errores de implementación más comunes y peligrosos en el control de acceso.

---

### 🌐 Ejemplo básico de IDOR:

Un usuario autenticado accede a su perfil personal mediante la siguiente URL:
```
GET /profile?id=102
```

Pero si el atacante cambia el valor del parámetro manualmente:
```
GET /profile?id=101
```

Y puede acceder al perfil de otro usuario sin estar autorizado, entonces estamos frente a un caso clásico de IDOR.

---

### 🔒 Impacto de un IDOR:

- Acceso no autorizado a información confidencial (emails, números de tarjeta, documentos).
- Posibilidad de modificar o eliminar recursos ajenos (por ejemplo: eliminar facturas, editar configuraciones, etc).
- Escalada horizontal o vertical de privilegios si el recurso afectado está vinculado a funcionalidades privilegiadas.

---

### 🤔 ¿Cómo se explota un IDOR?

El atacante suele realizar "parameter tampering", es decir, manipular parámetros en la URL, cookies o cuerpos de peticiones POST:

- Identificadores numéricos: `/invoice/3489`
- UUIDs: `/download?file=68ad2d02-7821-4a6d-bde3-849aa102ab5e`
- Nombres de archivo: `/uploads/john_resume.pdf`

Muchas veces los valores se predicen, descubren mediante fuzzing, o se extraen desde otras funcionalidades (como listados de usuarios, mensajes o historial).

---

### 🌍 Casos reales conocidos

- **Facebook IDOR**: vulnerabilidad en 2015 permitió ver fotos privadas de usuarios modificando IDs en peticiones.
- **Instagram IDOR**: filtración de información personal a través de manipulación de IDs en el endpoint de comentarios.

---

### 🚫 Prevención de IDOR:

1. **Evitar confiar en datos del cliente** para la autorización.
2. **Validar en el servidor** que el recurso solicitado pertenece al usuario autenticado.
3. **Diseñar el acceso mediante identificadores internos o referencias opacas**, no IDs predecibles.
4. **Implementar controles de acceso por objeto**, por ejemplo:
```python
if current_user.id != resource.owner_id:
    return HTTP 403 Forbidden
```
5. **Auditorías y pruebas de pentesting** centradas en horizontal privilege escalation.

---

### 🎓 Conclusión

Los IDOR representan una de las formas más comunes y peligrosas de vulnerabilidades en aplicaciones modernas. Su explotación puede realizarse con herramientas básicas y conocimiento mínimo del sistema, por lo que su mitigación debe ser prioridad. Al implementar un modelo de control de acceso robusto y evitar decisiones de autorización en el lado cliente, las organizaciones pueden protegerse eficazmente contra esta clase de fallas.



[Lab: Insecure direct object references](9_Insecure_direct_object_references.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)

---

### 🔒 Prevención de vulnerabilidades de acceso

1. **Verificar roles y permisos en el backend, siempre**.
2. **Nunca confiar en datos enviados por el cliente** (como IDs, roles, flags de admin).
3. **Implementar RBAC o controles programáticos robustos**.
4. **No exponer endpoints sensibles sin protección**.
5. **Auditar código y rutas ocultas o abandonadas (legacy)**.
6. **Realizar pentesting específico de control de acceso**: fuzzing de rutas, manipulación de IDs, tests de roles cruzados.

---



