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

[Lab: Information disclosure in error messages](1_Information_disclosure_in_error_messages.md)  

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



