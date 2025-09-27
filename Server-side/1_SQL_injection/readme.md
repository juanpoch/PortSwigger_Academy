# SQL injection


**SQL Injection** es una vulnerabilidad de seguridad web que permite a un atacante interferir en las consultas que una aplicación realiza a su base de datos. A través de esta técnica, el atacante puede:

- Visualizar datos que normalmente debería estar restringidos (por ejemplo, datos de otros usuarios).
- Modificar o eliminar datos, afectando el contenido y el comportamiento de la aplicación de manera persistente.
- Comprometer el servidor subyacente o infraestructura de backend.
- Realizar ataques de denegación de servicio.

En definitiva, permite manipular las instrucciones SQL que ejecuta el servidor.

---

### 🚫 Impacto de un ataque exitoso de SQL Injection

Un ataque de SQLi exitoso puede derivar en:

- **Acceso no autorizado** a datos sensibles como:
  - Contraseñas.
  - Detalles de tarjetas de crédito.
  - Información personal de usuarios.

- **Daños reputacionales** y sanciones regulatorias debido a la exposición de datos.

- **Instalación de backdoors** persistentes que permiten mantener el acceso a los sistemas a largo plazo sin ser detectados.

Históricamente, muchas filtraciones de datos de alto perfil se han debido a vulnerabilidades de tipo SQLi.

---

### 🔍 Cómo detectar vulnerabilidades de SQL Injection

Existen diversas técnicas manuales para identificar SQLi:

1. **Inserción de comillas simples (')**
   - Enviar `'` en los puntos de entrada.
   - Observar si se generan errores o comportamientos anómalos.

2. **Sintaxis SQL específica**
   - Utilizar payloads que, en condiciones normales, no deberían alterar la respuesta, y compararlo con payloads que cambian el comportamiento.

3. **Condiciones booleanas**
   - Inyectar `OR 1=1` y `OR 1=2`.
   - Comparar si la respuesta difiere según la condición.

4. **Payloads de retraso de tiempo (time-based)**
   - Utilizar instrucciones que retrasen la ejecución (por ejemplo, `SLEEP(5)`).
   - Detectar tiempos de respuesta anormales.

5. **Payloads Out-of-Band (OAST)**
   - Inyectar consultas que generen conexiones hacia servidores controlados por el atacante.

**Automatización:** Herramientas como **Burp Scanner** permiten encontrar vulnerabilidades SQLi de forma rápida y confiable.

---

### 🔹 SQL Injection en diferentes partes de una consulta

Aunque la mayoría de las vulnerabilidades ocurren en la cláusula **WHERE** de consultas **SELECT**, SQLi puede presentarse en múltiples ubicaciones:

- **UPDATE:** en los valores actualizados o en la condición WHERE.
- **INSERT:** en los valores insertados.
- **SELECT:** en los nombres de tablas o columnas.
- **ORDER BY:** manipulando el ordenamiento.

**Conclusión:** No se debe asumir que solo los filtros de búsqueda son vulnerables; cualquier parte que involucre entrada de usuario puede ser peligrosa.

---

### 📉 Ejemplos de ataques de SQL Injection

#### 1. Recuperación de datos ocultos

**Escenario:**

Un sitio de compras muestra productos por categoría. Al seleccionar "Gifts", el navegador envía:

```url
https://insecure-website.com/products?category=Gifts
```

Esto genera la consulta SQL:

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

* `released = 1` limita la muestra a productos marcados como "liberados" o publicados.

| Parte                | Explicación                                                                                                                              |
| :------------------- | :--------------------------------------------------------------------------------------------------------------------------------------- |
| `SELECT *`           | Selecciona todas las columnas de la tabla indicada.                                                                                      |
| `FROM products`      | Especifica la tabla de la que se extraerán los datos. En este caso, la tabla se llama `products`.                                        |
| `WHERE`              | Añade una condición: solo se devolverán los registros que cumplan los criterios especificados.                                           |
| `category = 'Gifts'` | Primera condición: el valor de la columna `category` debe ser igual a `'Gifts'`. Filtra los productos de la categoría "Gifts" (regalos). |
| `AND released = 1`   | Segunda condición: además, el valor de la columna `released` debe ser `1`. Esto indica que el producto debe estar liberado o publicado.  |

En otras palabras, la consulta significa: **“Selecciona todas las columnas de todas las filas de la tabla `products` en las que la columna `category` sea `'Gifts'` y la columna `released` tenga el valor `1`.”**

**Ataque:**

Un atacante puede modificar la URL:

```url
https://insecure-website.com/products?category=Gifts'--
```

Esto genera la consulta:

```sql
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
```

El `--` indica comentario en SQL, ignorando el `AND released = 1`. Resultado: **se muestran productos no publicados**.

**Expansión del ataque:**

```url
https://insecure-website.com/products?category=Gifts'+OR+1=1--
```

Resultado:

```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
```
- La consulta modificada devuelve todos los elementos donde el valor `category` es `Gifts` o devuelve todos los elementos donde `1=1`.
- Como `1=1` siempre es verdadero en todos los elementos, **todos** los productos son devueltos.

**Advertencia:**

Usar `OR 1=1` puede ser peligroso si el dato inyectado se reutiliza en otras consultas, como **UPDATE** o **DELETE**, lo cual podría eliminar o modificar datos críticos.

[Lab: SQL Injection vulnerability in WHERE clause allowing retrieval of hidden data](1_SQL_injection_vulnerability_in_WHERE_clause_allowing_retrieval_of_hidden_data.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)  


#### 2. Subversión de la lógica de aplicación

Un atacante puede alterar consultas para, por ejemplo, **saltarse** validaciones de usuario:

Entrada original:

```sql
SELECT * FROM users WHERE username = '[USERNAME]' AND password = '[PASSWORD]'
```
Si la consulta devuelve los datos de un usuario, el inicio de sesión se ha realizado correctamente. De lo contrario, se rechaza.
Inyección:

```
' OR 1=1 --
```

Consulta resultante:

```sql
SELECT * FROM users WHERE username = '' OR 1=1 --' AND password = ''
```

- El atacante logra iniciar sesión sin credenciales.
La base de datos va a devolver el primer registro que coincida con la condición.

- Como 1=1 siempre es cierto, la consulta puede devolver:

 - El primer usuario que esté en la tabla users.


O podríamos inyectar: `administrator'--`
Lo cual la consulta quedaría así:
```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```
Esta consulta devuelve el usuario cuyo `username` es `administrator` y registra exitosamente al atacante como ese usuario.  

[Lab: SQL injection vulnerability allowing login bypass](2_SQL_injection_vulnerability_allowing_login_bypass.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)  

#### 3. Ataques UNION

Permiten combinar resultados de distintas tablas.

**Ejemplo:**

```url
https://insecure-website.com/products?category=Gifts'+UNION+SELECT+username,password+FROM+users--
```

- Se obtienen nombres de usuario y contraseñas.

#### 4. Blind SQL Injection

Cuando la aplicación **no devuelve** directamente los datos en la respuesta:

- Se basa en diferencias de tiempo o en respuestas booleanas para inferir la información.
- Ejemplo de time-based blind:

```sql
IF (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin') = 'a' THEN SLEEP(5)
```

Si la respuesta se demora, el atacante deduce que la condición fue verdadera.

---

### 🔧 Buenas prácticas de prevención

- **Uso de consultas preparadas (prepared statements)** o **consultas parametrizadas**.
- **Validación estricta** y saneamiento de entradas.
- **Principio de privilegios mínimos**: la base de datos debería operar con usuarios de bajo privilegio.
- **Uso de ORM seguros** que abstraen las consultas SQL.
- **Monitoreo de actividad anormal** en bases de datos.

---

### 💬 Resumen

**SQL Injection** sigue siendo una de las vulnerabilidades más críticas en aplicaciones web. Un pequeño descuido en la validación de datos de entrada puede abrir la puerta a ataques que comprometan la confidencialidad, integridad y disponibilidad de los datos y sistemas. Conocer sus fundamentos, ejemplos y mecanismos de mitigación es fundamental para todo desarrollador y analista de seguridad.

---

### 💡¡Recuerda!

> "Una aplicación web es tan segura como la confianza que puede depositarse en sus consultas de base de datos."


