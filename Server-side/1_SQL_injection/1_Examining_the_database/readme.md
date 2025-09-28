# Examining the database

**Propósito:** describir cómo obtener información sobre la base de datos una vez que se ha identificado una vulnerabilidad de SQL injection. Incluye técnicas de *fingerprinting*, consultas útiles para listar versiones, tablas y columnas, diferencias entre sistemas gestores de bases de datos, y recomendaciones de mitigación.

[SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

---

## Resumen

Cuando encuentras una inyección SQL, el siguiente paso racional es **examinar** la base de datos: conocer el tipo de SGBD (MySQL, PostgreSQL, Microsoft SQL Server, Oracle, SQLite, etc.), su versión, las tablas disponibles y las columnas que contienen. Esta información facilita la explotación (por ejemplo con `UNION SELECT`, subconsultas o inyecciones ciegas) y ayuda a construir payloads más precisos.

Sin embargo, cada SGBD tiene diferencias sintácticas y de comportamiento que afectan las técnicas: concatenación de cadenas, comentarios, manejo de errores, soporte de consultas apiladas (stacked queries), vistas del sistema, funciones/version, y APIs específicas. Por eso es crucial *fingerprintear* el motor antes de profundizar.

---

## ¿Por qué examinar la base de datos?

* **Elegir técnicas de explotación apropiadas.** Algunas técnicas (p. ej. `UNION`) requieren conocer el número de columnas y tipos; otras (p. ej. `SLEEP`) se usan en inyecciones por tiempo.
* **Encontrar tablas y columnas relevantes.** Buscar tablas `users`, `account`, `credentials`, `admin`, etc., o columnas como `password`, `email`.
* **Identificar APIs/funciones peligrosas.** Algunas bases permiten ejecutar comandos del sistema mediante funciones/procedimientos (ej. `xp_cmdshell` en SQL Server, `UTL_FILE` en Oracle).
* **Estimar el impacto.** Saber si la base es una instancia de producción, qué versión corre y qué permisos existen contribuye al análisis de riesgo.

---

## Técnicas de fingerprint (identificación del SGBD)

1. **Errores devueltos por la aplicación.** Mensajes con stack traces, nombres de funciones o errores SQL suelen indicar el motor (ej. mensajes con `ORA-` → Oracle; `Microsoft OLE DB Provider` → SQL Server; `pg_` o `syntax error at or near` → PostgreSQL; `SQLSTATE` + `MySQL` → MySQL).

2. **Funciones/constructos que prueban si existen.** Ejecutar consultas que usan funciones específicas y observar la respuesta o el error. Ejemplos:

   * `SELECT version()` → PostgreSQL, MySQL (en MySQL devuelve valor con `SELECT VERSION()` también).
   * `SELECT @@version` → MySQL / SQL Server (en SQL Server `@@version` también funciona).
   * `SELECT * FROM v$version` → Oracle (vista específica de Oracle).

3. **Sintaxis de concatenación y operadores.** Probar operadores `||`, `+`, `CONCAT()`:

   * `||` suele funcionar en Oracle y PostgreSQL.
   * `+` suele funcionar en Microsoft SQL Server (para strings).
   * `CONCAT()` es común en MySQL y también existe en otros motores.

4. **Comentarios soportados.** Probar `--`, `/*...*/`, `#` (este último es típico de MySQL para queries en línea). Si `#` genera error probablemente no sea MySQL.

5. **Soporte de queries apiladas (stacked queries).** Intentar `;` para encadenar consultas. Algunos motores o configuraciones web impiden enviar múltiples sentencias en una petición SQL (dependiendo del API de la aplicación). MySQL y SQL Server *pueden* soportarlas en ciertos contextos; PostgreSQL y Oracle suelen restringirlas si la API no lo permite.

6. **Tablas del diccionario de datos.** Consultas a `information_schema`, `pg_catalog`, `all_tables`, `user_tables`, `sqlite_master` dan pistas directas del motor.

---

## Vistas y consultas útiles por SGBD

> **Nota:** ejecutar estas consultas desde la aplicación vulnerable sólo si estás autorizado (labs o pentest autorizado). Muchas apps sanitizan la salida; adapta payloads para que los resultados aparezcan en el contenido que la app muestra (por ejemplo, usando `UNION` para insertar resultados en la respuesta HTML).

### Consultas para obtener versión

* **MySQL** / **MariaDB**

  ```sql
  SELECT VERSION();
  SELECT @@version;
  ```

* **PostgreSQL**

  ```sql
  SELECT version();
  ```

* **Microsoft SQL Server**

  ```sql
  SELECT @@version;
  -- o
  SELECT SERVERPROPERTY('ProductVersion'), SERVERPROPERTY('ProductLevel'), SERVERPROPERTY('Edition');
  ```

* **Oracle**

  ```sql
  SELECT * FROM v$version;
  -- o
  SELECT version FROM v$instance; -- según permisos
  ```

* **SQLite**

  ```sql
  SELECT sqlite_version();
  ```

### Consultas para listar tablas

* **Estándar (funciona en MySQL, PostgreSQL, SQL Server si existe information_schema):**

  ```sql
  SELECT table_schema, table_name
  FROM information_schema.tables
  WHERE table_type = 'BASE TABLE' -- o 'VIEW' según interés
  ORDER BY table_schema, table_name;
  ```

* **PostgreSQL (alternativa):**

  ```sql
  SELECT schemaname, tablename FROM pg_catalog.pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema');
  ```

* **Oracle:**

  ```sql
  SELECT owner, table_name FROM all_tables; -- necesita permisos
  SELECT table_name FROM user_tables; -- tablas del usuario actual
  ```

* **SQL Server (otra opción):**

  ```sql
  SELECT name, schema_name(schema_id) FROM sys.tables;
  ```

* **SQLite:**

  ```sql
  SELECT name, type FROM sqlite_master WHERE type='table';
  ```

### Consultas para listar columnas / esquema de una tabla

* **Estándar (information_schema.columns):**

  ```sql
  SELECT table_schema, table_name, column_name, data_type
  FROM information_schema.columns
  WHERE table_name = 'users'
  ORDER BY ordinal_position;
  ```

* **PostgreSQL:**

  ```sql
  SELECT column_name, data_type FROM information_schema.columns WHERE table_name='users';
  -- o
  SELECT attname, format_type(atttypid, atttypmod) FROM pg_attribute WHERE attrelid = 'users'::regclass AND attnum > 0;
  ```

* **Oracle:**

  ```sql
  SELECT column_name, data_type FROM all_tab_columns WHERE table_name='USERS';
  ```

* **SQLite:**

  ```sql
  PRAGMA table_info('users');
  ```

* **SQL Server:**

  ```sql
  SELECT c.name, t.name AS data_type
  FROM sys.columns c
  JOIN sys.types t ON c.user_type_id = t.user_type_id
  WHERE c.object_id = OBJECT_ID('dbo.users');
  ```

---

## Diferencias prácticas entre SGBD (resumen)

| Área                   |                                         MySQL / MariaDB | PostgreSQL                         |                   Microsoft SQL Server | Oracle                      | SQLite                                        |    |                   |    |   |    |    |   |    |
| ---------------------- | ------------------------------------------------------: | ---------------------------------- | -------------------------------------: | --------------------------- | --------------------------------------------- | -- | ----------------- | -- | - | -- | -- | - | -- |
| Concatenación          |                                      `CONCAT(a,b)` ó `a |                                    | b`(en MySQL modern puede usar`CONCAT`) | `a                          |                                               | b` | `a + b` (strings) | `a |   | b` | `a |   | b` |
| Comentarios            |                             `-- `, `/* */`, `#` (MySQL) | `-- `, `/* */`                     |                         `-- `, `/* */` | `-- `, `/* */`              | `-- `, `/* */`                                |    |                   |    |   |    |    |   |    |
| Version function       |                               `VERSION()` / `@@version` | `version()`                        |       `@@version` / `SERVERPROPERTY()` | `v$version`                 | `sqlite_version()`                            |    |                   |    |   |    |    |   |    |
| Información de esquema |                                    `information_schema` | `information_schema`, `pg_catalog` |          `INFORMATION_SCHEMA`, `sys.*` | `ALL_TABLES`, `USER_TABLES` | `sqlite_master`                               |    |                   |    |   |    |    |   |    |
| Stacked queries        | posible con flag `--multiple`/client; a veces permitido | a menudo NO en APIs web            |           permitido en muchos entornos | a menudo NO en APIs web     | NO (no en contexto SQL de la mayoría de apps) |    |                   |    |   |    |    |   |    |
| Mensajes de error      |                         Verbosos si no están suprimidos | Verbosos                           |                               Verbosos | Mensajes `ORA-`             | Mensajes limitados (embebido)                 |    |                   |    |   |    |    |   |    |

## Comentarios, concatenación y ejemplos sintácticos

* **Comentarios:**

  * `-- ` : comentario de línea (suele necesitar espacio después de `--` en algunos SGBD)
  * `/* ... */` : comentario de bloque (multi-line)
  * `#` : comentario de línea (típico de MySQL)

* **Concatenación de cadenas:**

  * MySQL: `CONCAT('a','b')` → `'ab'`
  * PostgreSQL / Oracle / SQLite: `'a' || 'b'` → `'ab'`
  * SQL Server: `'a' + 'b'` → `'ab'`

Usar la forma correcta ayuda a construir payloads que devuelvan datos visibles en la respuesta.

---

## Técnicas de enumeración y ejemplos conceptuales

> A continuación hay ejemplos conceptuales pensados para laboratorios y aprendizaje. Adapta los payloads para que la salida resultante se muestre en la aplicación (p.ej. inyectando en columnas que la página renderiza o usando `UNION`).

### 1) Obtener la versión (fingerprint)

* **MySQL / PostgreSQL / SQLite:** `SELECT version();`
* **SQL Server:** `SELECT @@version;`
* **Oracle:** `SELECT * FROM v$version;`

Mostrar la cadena de versión en la página permite confirmar el motor.

### 2) Listar tablas usando `information_schema`

```sql
SELECT table_schema, table_name
FROM information_schema.tables
WHERE table_type='BASE TABLE'
ORDER BY table_schema, table_name;
```

Si la página renderiza resultados tabulares, puedes usar `UNION SELECT` para insertar el resultado en la respuesta visible.

### 3) Enumerar columnas de `users`

```sql
SELECT column_name, data_type FROM information_schema.columns WHERE table_name='users';
```

### 4) Exfiltrar datos: `UNION` y `GROUP_CONCAT` (concepto)

* En MySQL, `GROUP_CONCAT` agrupa filas en una sola cadena; útil cuando la app muestra un único campo.
* En PostgreSQL existe `string_agg()` para similar propósito.

Ejemplo conceptual (MySQL):

```sql
-- obtener username:password concatenados
SELECT GROUP_CONCAT(CONCAT(username,':',password) SEPARATOR ',') FROM users;
```

En otros SGBD se usan funciones equivalentes o concatenación con `||`.

### 5) Inyección ciega (time-based) para motores que soportan `SLEEP` o `pg_sleep`

* MySQL: `SLEEP(n)`
* PostgreSQL: `pg_sleep(n)`
* SQL Server: `WAITFOR DELAY '00:00:05'`

Ejemplo conceptual para comprobar si primer carácter del password de `admin` es `a` (MySQL):

```sql
-- IF(CONDITION, SLEEP(5), 0) -> provoca retraso si se cumple
SELECT IF(SUBSTRING((SELECT password FROM users WHERE username='admin' LIMIT 1),1,1)='a', SLEEP(5), 0);
```

En PostgreSQL usar `CASE WHEN ... THEN pg_sleep(5) ELSE 0 END`.

---

## Mensajes de error y cómo usarlos (error-based)

* **Error-based SQLi** fuerza la base a producir un error que incluya datos (por ejemplo, usando `CAST`/`CONCAT` en un contexto que cause overflow o `GROUP BY` con `RAND()` en MySQL). Estos mensajes son muy útiles cuando la aplicación devuelve el texto de error tal cual.
* Ejemplo de pistas en errores:

  * `ORA-` → Oracle
  * `SQLSTATE` con `MySQL` o texto con `mysql_real_query` → MySQL
  * `syntax error at or near` → PostgreSQL
  * `Incorrect syntax near` / `Microsoft OLE DB Provider` → SQL Server

> **Precaución:** en entornos reales de producción los errores suelen estar suprimidos. En labs de PortSwigger muchas respuestas devuelven errores explícitos para practicar.

---

## APIs / funcionalidades peligrosas por SGBD (para evaluar impacto)

* **SQL Server**: `xp_cmdshell` (ejecución de comandos del SO) — suele estar desactivado por defecto.
* **Oracle**: paquetes `DBMS_XDB`, `UTL_HTTP`, `UTL_FILE`, `DBMS_OUTPUT` — algunos permiten acceso externo o escritura en archivos.
* **MySQL**: `SELECT ... INTO OUTFILE` (si se tienen permisos), `LOAD_FILE()`.
* **PostgreSQL**: `COPY ... TO PROGRAM` (en versiones con permiso), `pg_read_file()` (según configuración y permisos).

Encontrar que la base tiene permisos para estas operaciones incrementa el riesgo (e.g., exfiltración a un fichero, ejecución remota, etc.).

---

## Buenas prácticas de detección y pruebas en labs

* **Identifica primero el SGBD**: pruebas muy orientadas a un motor evitan "ruido" y fallos por sintaxis inapropiada.
* **Empieza con consultas inofensivas**: `SELECT version()` o `SELECT 1` para ver la respuesta.
* **Evita causar daño**: en un pentest autorizado o lab, no intentes destruir datos. En entornos reales, obtén permiso explícito.
* **Automatiza con responsabilidad**: herramientas como `sqlmap` ayudan, pero primero haz fingerprint manual para dirigir la herramienta correctamente y evitar consultas ruidosas.
* **Documenta payloads y resultados**: en tus writeups incluye requests/responses, capturas y la lógica usada para adaptar consultas según el motor.

---

## Mitigaciones y recomendaciones de seguridad

1. **Prepared statements / consultas parametrizadas** — la defensa principal contra SQLi.
2. **Validación y saneamiento estricto de entrada** — whitelisting preferible a blacklisting.
3. **Menos privilegios en la cuenta DB** — evitar cuentas con permisos excesivos (ej. `FILE`, `xp_cmdshell`).
4. **Ocultar mensajes de error** — no devolver errores detallados al cliente.
5. **WAF y detección** — reglas de WAF ayudan pero no reemplazan código seguro.
6. **Registro y alertas** — detectar patrones anómalos (queries largas, uso de funciones inusuales, tiempos de espera excesivos).

---

## Recursos y referencias rápidas

* `information_schema` — estándar para metadatos (tablas, columnas). Funciona en MySQL, PostgreSQL, SQL Server (en gran medida).
* `pg_catalog` — catálogo de PostgreSQL.
* `v$version`, `all_tables`, `user_tables` — Oracle.
* `sqlite_master` y `PRAGMA` — SQLite.

---

