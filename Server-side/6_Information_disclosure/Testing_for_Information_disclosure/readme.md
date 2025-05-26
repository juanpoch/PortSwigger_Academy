# 🔎 Cómo encontrar y explotar vulnerabilidades de divulgación de información

Esta sección proporciona consejos prácticos, técnicas y herramientas para identificar vulnerabilidades de divulgación de información en una amplia variedad de contextos. Estas técnicas son fundamentales para cualquier tester, ya que permiten detectar datos sensibles ocultos que pueden abrir la puerta a ataques más graves. La habilidad de reconocer esta información, incluso cuando se encuentra de forma indirecta, es una de las claves del pentesting eficaz.

---

## 📂 Cómo testear vulnerabilidades de divulgación de información

### Evitar la visión de túnel
Uno de los errores más comunes durante las pruebas es desarrollar "visión de túnel", es decir, enfocarse demasiado en una sola vulnerabilidad específica y pasar por alto datos o comportamientos relevantes. La divulgación de información puede encontrarse en múltiples lugares: mensajes de error, respuestas HTTP, código fuente, comentarios HTML, cabeceras, archivos olvidados, entre otros. 

Un buen pentester debe estar siempre atento a:

- Cambios sutiles en los tiempos de respuesta.
- Diferencias en los códigos de estado HTTP.
- Mensajes de error más detallados de lo habitual.
- Palabras clave como `error`, `exception`, `warning`, `password`, `SQL`, `debug`, `trace`, etc.

---

## ⚙️ Herramientas y técnicas útiles

### 🔮 Fuzzing

El fuzzing en este caso consiste en enviar datos inesperados a los parámetros identificados para provocar errores o respuestas inusuales que revelen información sensible. Algunos ejemplos:

- Enviar tipos de datos inesperados: strings en lugar de números, símbolos especiales (`%`, `"`, `&`, `<`, `>`), booleanos, etc.
- Introducir payloads conocidos como `'||1=1--`, `' OR 'x'='x`, `../../../../etc/passwd`, entre otros.

Usar herramientas como **Burp Intruder** permite automatizar este proceso y obtener ventajas como:

- Reenvío masivo de payloads desde listas predefinidas.
- Comparación automática de respuestas por longitud, código de estado, tiempo de respuesta.
- Uso de *grep match* para detectar palabras clave en las respuestas.
- Uso de *grep extract* para extraer valores de campos específicos.

Además, extensiones como **Logger++** del BApp Store de Burp ayudan a registrar todas las solicitudes y filtrar aquellas con información relevante de forma más visual y avanzada.

### 🔍 Usar Burp Scanner (versión Professional)

**Burp Scanner** permite auditar automáticamente una aplicación mientras navegás o bien mediante escaneo automatizado. Este identificará múltiples formas de divulgación de información:

- Claves privadas.
- Correos electrónicos.
- Archivos de respaldo.
- Directorios listados.
- Información de versiones.

### ⚖️ Usar herramientas de "Engagement"

Desde cualquier entrada en Proxy, Site Map o HTTP history podés hacer clic derecho y seleccionar **Engagement tools**. Las herramientas más relevantes para disclosure son:

- **Search**: Buscar expresiones (como palabras clave sensibles) usando regex o filtros avanzados.
- **Find comments**: Detectar comentarios HTML ocultos por los desarrolladores.
- **Discover content**: Ejecuta un *content discovery* para encontrar recursos no enlazados, como paneles de admin, backups, endpoints API, rutas internas, etc.

---

## 💡 Ingeniería de respuestas informativas

Un ataque más sofisticado consiste en manipular la aplicación para que genere respuestas de error que revelen información útil:

- Forzar errores que disparen *stack traces* o respuestas de depuración.
- Realizar acciones inválidas (como acceder a recursos inexistentes) para observar diferencias en los mensajes de error.

**Ejemplo práctico:**

Si el endpoint `/user?id=123` responde con "User not found" pero `/user?id=999` lanza una excepción como `NullPointerException`, esto revela que 123 es un usuario válido aunque no se devuelva ningún dato.

---

## 📝 Fuentes comunes de divulgación de información

### ✉️ Archivos para web crawlers

- `/robots.txt` y `/sitemap.xml` muchas veces contienen rutas sensibles que los desarrolladores no quieren indexar.
- Estas rutas pueden incluir `/admin/`, `/backup/`, `/staging/`, etc.
- Accedé manualmente a `/robots.txt` para ver qué rutas están ocultas.

### 🗂️ Directory listings

- Cuando no hay un archivo `index.html` en un directorio, muchos servidores muestran la lista de archivos.
- Esto permite a un atacante ver archivos sensibles como `config.bak`, `debug.log`, `db.sql`, etc.

**Ejemplo:**

```
http://site.com/backup/
→ muestra: config.php, db_backup.sql
```

### 📊 Comentarios de desarrollador

- Comentarios HTML como `<!-- TODO: implement authorization -->` pueden revelar endpoints futuros, lógicas incompletas o advertencias internas.
- No son visibles para el usuario, pero sí en el código fuente y herramientas como Burp.

### ❌ Mensajes de error

- Mensajes verbosos pueden mostrar:
  - Stack traces.
  - Tecnología usada (Spring, Laravel, Express, etc).
  - Versión de frameworks o bibliotecas.
  - SQL queries o rutas internas.

**Ejemplo:**

Un error como:
```sql
ERROR: column "username" does not exist in SELECT * FROM users WHERE username = 'foo'
```
revela el nombre de la tabla (`users`) y la columna (`username`).

También pueden sugerir vectores de ataques:

- Si un error cambia dependiendo del input, puede ser útil para **enumerar usuarios**, **SQLi**, **blind XSS**, etc.

---

## 🔒 Impacto y evaluación de severidad

- **Divulgación directa**: Cuando la información expuesta tiene valor intrínseco (nombres de usuario, tarjetas de crédito, contraseñas, etc).
- **Divulgación indirecta**: Cuando la información técnica sirve como base para un ataque más complejo (por ejemplo, identificar que se usa una versión vulnerable de Apache Struts).

**Regla de oro**: si podés demostrar cómo una pieza de información técnica facilita otro ataque, entonces el hallazgo escala en severidad.


[Lab: Information disclosure in error messages](1_Information_disclosure_in_error_messages.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

## 🔞 Debugging Data: Una fuente crítica de información expuesta

Durante la etapa de desarrollo, es común que las aplicaciones web incluyan mecanismos de **debugging** o depuración para ayudar a los desarrolladores a identificar errores de lógica, fallas en el backend o problemas de integración. Estas herramientas, aunque fundamentales durante la construcción de software, **pueden convertirse en una seria amenaza si no son desactivadas correctamente antes de pasar a producción**.

### 💥 ¿Qué es el debugging data?

Se refiere a cualquier tipo de información generada automáticamente por la aplicación para mostrar detalles sobre su funcionamiento interno. Esto puede manifestarse en distintas formas:

- **Mensajes de error detallados (verbose errors)** que explicitan:
  - Funciones internas ejecutadas
  - Variables utilizadas
  - Stack traces (pila de ejecución)
  - Nombre de archivos o rutas del sistema
  - Módulos o dependencias de terceros
- **Logs de aplicación** accesibles desde la web
- **Mensajes de consola** visibles en respuestas HTTP o código fuente
- **Flags de entorno** activadas como `DEBUG=True` en frameworks como Flask o Django

---

### 🔍 Ejemplos comunes de información crítica expuesta

| Información filtrada         | Riesgo asociado                                  |
|------------------------------|--------------------------------------------------|
| Stack traces                 | Revela rutas internas, clases, errores internos  |
| Variables de sesión         | Manipulación de estado o suplantación de identidad|
| Credenciales de backend      | Acceso a DBs, servicios internos o APIs          |
| Claves criptográficas        | Compromete cifrado de datos                      |
| Hostnames internos           | Facilita ataques SSRF o movimiento lateral       |

#### 📌 Ejemplo real: Django y `DEBUG=True`

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'appdb',
        'USER': 'admin',
        'PASSWORD': 'supersecretpass',
    }
}
```

Una excepción simple puede exponer toda esta configuración.

---

### 🔎 Acceso a archivos de depuración

Muchas veces los errores no están en la interfaz web, pero sí en **archivos `.log`** internos del servidor, como:

```
/var/log/app/error.log
/app/logs/debug.log
```

Si estos logs son accesibles por HTTP sin autenticación, se puede obtener:

- Errores recientes
- Inputs maliciosos enviados
- Tokens de sesión
- Variables de entorno

#### 🔮 Ejemplo de URL sensible

```
https://vulnerable-site.com/logs/debug.log
```

---

### 🤕 Cómo explotar debugging data en un pentest

1. **Forzar errores**: enviar tipos inesperados (null, strings enormes).
2. **Buscar rutas comunes**: `/logs/`, `/debug/`, `/app/debug.log`, etc.
3. **Observar códigos 500**: muchas veces traen HTML con stack trace.
4. **Buscar en HTML**: comentarios como `<!-- DEBUG: api_key = abc123 -->`

---

### 🛡️ Recomendaciones para prevenir

- Nunca dejar debugging activo en producción (`DEBUG=False`).
- Bloquear acceso a carpetas de logs por HTTP.
- Usar manejadores de errores personalizados.
- Automatizar detección de debugging con scripts QA.

---

### 🎯 En resumen

El debugging data puede ser una mina de oro para un atacante. Muchas veces es el **primer paso para una cadena de exploits más compleja**. Saber reconocerlo e interpretarlo es esencial para cualquier pentester, y deshabilitarlo correctamente es fundamental para cualquier desarrollador.

[Lab: Information disclosure on debug page](2_Information_disclosure_on_debug_page.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

# Páginas de cuenta de usuario y archivos de respaldo

## Páginas de cuenta de usuario

Por naturaleza, las páginas de perfil o cuenta de un usuario suelen contener información sensible, como el correo electrónico, número de teléfono, clave API, entre otros. Dado que los usuarios normalmente solo tienen acceso a su propia página de cuenta, esto no representa una vulnerabilidad en sí mismo. Sin embargo, algunos sitios contienen fallos de lógica que potencialmente permiten a un atacante aprovechar estas páginas para visualizar los datos de otros usuarios.

Por ejemplo, consideremos un sitio que determina qué página de cuenta cargar basándose en un parámetro `user`:

```
GET /user/personal-info?user=carlos
```

La mayoría de los sitios web implementan medidas para evitar que un atacante simplemente cambie ese parámetro y acceda a las páginas de otros usuarios. Sin embargo, a veces la lógica para cargar elementos individuales de datos no es tan robusta.

Es posible que un atacante no pueda cargar completamente la página de cuenta de otro usuario, pero que sí pueda explotar un fallo en la lógica que recupera y muestra, por ejemplo, el correo electrónico del usuario. Si esa lógica no valida que el parámetro `user` coincida con el usuario actualmente autenticado, bastará con modificar ese parámetro para revelar el correo electrónico de cualquier otro usuario.

Este tipo de problemas son un caso común de vulnerabilidades de control de acceso o IDOR (Insecure Direct Object References), las cuales analizaremos más adelante en profundidad.

---

## Divulgación de código fuente mediante archivos de respaldo

Obtener acceso al código fuente de una aplicación web facilita enormemente la tarea de comprender su funcionamiento interno y diseñar ataques de mayor severidad. En muchos casos, datos sensibles como claves de API o credenciales de acceso a componentes de backend están hardcodeados directamente en el código.

Si logramos identificar que la aplicación usa una tecnología de código abierto específica (por ejemplo, una versión conocida de WordPress, Laravel o Django), esto nos permite acceder a parte del código fuente ya documentado. Sin embargo, también puede ser posible acceder directamente al código personalizado del sitio web.

En algunos casos, el sitio web expone involuntariamente su propio código fuente. Durante la etapa de mapeo de un sitio, podrías descubrir que algunos archivos fuente son referenciados directamente en el frontend o desde JavaScript. Sin embargo, al solicitar dichos archivos, normalmente el servidor los ejecuta (por ejemplo, archivos `.php`) en lugar de devolverlos como texto plano. Pero bajo ciertas condiciones, esto puede ser evadido.

Una técnica común es buscar archivos temporales o de respaldo que los editores de texto generan automáticamente mientras se edita un archivo. Estos archivos suelen tener nombres similares al original pero con una pequeña modificación, como:

- `archivo.php~`
- `archivo.php.bak`
- `archivo.old`
- `archivo.php.save`
- `.#archivo.php`
- `archivo.php.swp` (tipos usados por editores como `vi` o `vim`)

Si el servidor no tiene restricciones que impidan acceder a estos archivos, es posible que simplemente al solicitar la URL correspondiente se devuelva el contenido del archivo fuente en texto plano, permitiendo a un atacante analizarlo y extraer información crítica.

### 🧠 Ejemplo práctico
Supongamos que en un sitio descubrimos que existe `login.php`. Podemos probar solicitudes como:

```
GET /login.php~
GET /login.php.bak
GET /.login.php.swp
```

Si alguna de estas solicitudes responde con un `200 OK` y muestra contenido legible, significa que tenemos exposición directa al código fuente, lo cual podría revelar contraseñas, conexiones a base de datos o incluso rutas internas del servidor.

Este tipo de fallos no solo comprometen la confidencialidad de la aplicación, sino que suelen llevar directamente a la explotación de otras vulnerabilidades críticas, como RCE, LFI, bypass de autenticación, entre otros.

---

### ✅ Recomendaciones de mitigación

- No dejar archivos de respaldo, temporales o versiones antiguas accesibles en producción.
- Implementar reglas en el servidor (como `.htaccess` o configuraciones en Nginx) que bloqueen accesos a extensiones como `.bak`, `.old`, `.swp`, `.save`, etc.
- Auditar periódicamente el contenido de los servidores web y eliminar archivos innecesarios.
- Aplicar un control estricto de acceso a cualquier recurso que contenga código fuente o datos sensibles.

Estas medidas ayudan a reducir significativamente la superficie de ataque relacionada con la exposición accidental del código fuente o datos privados.

[Lab: Source code disclosure via backup files](3_Source_code_disclosure_via_backup_files.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

### Divulgación de Información por Configuración Insegura

Una de las fuentes más comunes de vulnerabilidades de divulgación de información en aplicaciones web se origina en **configuraciones incorrectas o inseguras**. Esto ocurre particularmente cuando se utilizan **tecnologías de terceros**, frameworks, bibliotecas o servidores cuyas opciones de configuración no son comprendidas en su totalidad por quienes las implementan.

#### 🔧 Causas Comunes de Configuración Insegura

1. **Uso de valores por defecto:**
   - Muchas veces se implementan servidores o aplicaciones sin cambiar las configuraciones por defecto.
   - Ejemplo: dejar activado el listado de directorios en Apache (`Options Indexes`).

2. **Exposición de herramientas de depuración en producción:**
   - Archivos como `phpinfo.php`, `debug_toolbar`, paneles administrativos, o verbose error pages.
   - Estas herramientas pueden exponer variables de entorno, rutas internas, claves, y configuraciones sensibles.

3. **Métodos HTTP habilitados innecesariamente:**
   - Algunos servidores responden a métodos como `TRACE`, `OPTIONS`, `PUT`, o `DELETE`, los cuales no son necesarios para una aplicación web común.
   
4. **Módulos de logging o verbose logs:**
   - Logs detallados accesibles públicamente o incluídos accidentalmente en el frontend (por ejemplo, mediante JavaScript).

5. **Servicios innecesarios expuestos:**
   - Servidores que corren servicios como Redis, Elasticsearch o bases de datos accesibles por IP pública sin autenticación.

---

#### 🔎 Caso específico: Método HTTP TRACE

El método TRACE fue diseñado para fines de depuración HTTP. Permite al cliente enviar una solicitud que es **devuelta tal como fue recibida** por el servidor. Esto puede parecer inofensivo, pero presenta riesgos importantes:

- Si hay **cabeceras internas** agregadas por proxies o firewalls (por ejemplo, `X-Auth-Token`, `X-Forwarded-For`), estas pueden ser **reveladas involuntariamente**.
- Puede ser explotado mediante un ataque **Cross-Site Tracing (XST)** si se combina con XSS, permitiendo a un atacante robar cookies o tokens.

**Ejemplo de prueba usando curl:**
```bash
curl -i -X TRACE https://vulnerable-site.com/
```

Si la respuesta incluye la solicitud original, el método TRACE está habilitado.

---

#### 🧰 Implicancias para la seguridad

- La configuración insegura **amplía la superficie de ataque** de forma innecesaria.
- Puede brindar a los atacantes **información crítica para la explotación de vulnerabilidades más severas** (como RCE, SQLi o LFI).
- Contribuye a vulnerabilidades del tipo **Information Disclosure**, **Misconfiguration**, y **Broken Access Control**.

---

#### 💪 Buenas prácticas de configuración segura

1. **Deshabilitar funcionalidades innecesarias:** TRACE, verbose logging, debug endpoints, métodos HTTP no requeridos.

2. **Usar headers de seguridad:**
   - `X-Frame-Options: DENY`
   - `X-Content-Type-Options: nosniff`
   - `Referrer-Policy`, `Permissions-Policy`, etc.

3. **Auditorías regulares de configuración:** tanto manuales como automatizadas, especialmente tras updates o deployments.

4. **Escaneo con herramientas de seguridad:** Burp Scanner, Nikto, Nuclei, o herramientas de SAST (Static Application Security Testing).

5. **Desplegar entornos segmentados:** Asegurarse de que desarrollo, staging y producción no compartan configuraciones inseguras ni accesos públicos.

---

La configuración insegura es una de las causas más frecuentes y evitables de filtración de datos. Aunque muchas veces es subestimada, puede convertirse en la pieza clave que habilita cadenas de ataque mucho más complejas.

[Lab: Authentication bypass via information disclosure](4_Authentication_bypass_via_information_disclosure.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)


---

## ✅ Prevención de vulnerabilidades de divulgación

1. **Eliminar contenido interno antes de producción**:
   - Comentarios HTML.
   - Archivos de prueba o backup.
2. **Deshabilitar diagnósticos y debug en producción**.
3. **Mensajes de error genéricos**.
4. **Auditoría de configuración y código fuente**.
5. **Conocimiento compartido**:
   - Capacitar al equipo en qué información es sensible.
   - Documentar y revisar configuraciones y despliegues.

---



