## ✅ Testing de APIs

### 🛠️ Introducción

Las APIs (Interfaces de Programación de Aplicaciones) permiten que distintos sistemas o aplicaciones intercambien datos. Las APIs son componentes fundamentales en cualquier sitio web moderno, por lo que las vulnerabilidades en ellas pueden afectar la **confidencialidad**, **integridad** y **disponibilidad** de una aplicación.

Incluso vulnerabilidades clásicas como **SQLi** pueden considerarse parte del testing de APIs. En esta guía, aprenderás a:

* Identificar APIs que no están directamente expuestas en el frontend.
* Probar APIs RESTful y basadas en JSON.
* Detectar vulnerabilidades como la **Server-Side Parameter Pollution (SSPP)**.

---

### 📋 Mapeo con OWASP API Security Top 10 2023

Las vulnerabilidades comunes en APIs coinciden con muchas de las del testing clásico de aplicaciones web. PortSwigger proporciona una tabla de correlación entre sus labs y el [OWASP API Security Top 10](https://owasp.org/www-project-api-security/).

---

## 🔍 Recolección de información (API Recon)

Antes de atacar una API, necesitás entender su **superficie de ataque**. Los pasos son:

### ✅ Identificar Endpoints

Un **endpoint** es una URL que representa un recurso y permite recibir solicitudes sobre él.

**Ejemplo**:

```http
GET /api/books HTTP/1.1
Host: example.com
```

El endpoint es `/api/books`, que podría devolver una lista de libros.

Otros ejemplos:

* `/api/users/123`
* `/api/products?category=toys`
* `/api/books/mystery`

### ✅ Determinar Interacción

Para probar efectivamente una API, necesitás conocer:

* Datos de entrada esperados (parámetros obligatorios y opcionales).
* Métodos HTTP aceptados (`GET`, `POST`, `PUT`, `DELETE`, etc.).
* Formatos soportados (`application/json`, `application/xml`).
* Reglas de autenticación y rate-limiting.

**Ejemplo de request válido:**

```json
POST /api/login HTTP/1.1
Content-Type: application/json
{
  "username": "juan",
  "password": "1234"
}
```

---

## 📖 Documentación de API

La documentación puede estar en dos formatos:

* **Legible por humanos**: explicaciones, ejemplos, cómo consumir los endpoints.
* **Legible por máquinas**: archivos estructurados (JSON, YAML, XML), como `swagger.json` o `openapi.yaml`.

Siempre revisá esta documentación para entender la funcionalidad y parámetros.

---

## 📑 Descubrimiento de documentación

Incluso si no está disponible públicamente, podés encontrarla explorando la aplicación con herramientas como **Burp Suite**.

### 📂 Rutas comunes a probar:

* `/api`
* `/swagger/index.html`
* `/swagger.json`
* `/openapi.json`

**Estrategia**:
Si encontrás un endpoint como:
`/api/swagger/v1/users/123`
Probar también:

* `/api/swagger/v1`
* `/api/swagger`
* `/api`

### 🔧 Herramientas

* **Burp Scanner**: escaneo automático de endpoints.
* **Intruder**: prueba con lista de rutas comunes para encontrar archivos de documentación.

**Consejo**: en Burp podés crear una wordlist con rutas comunes a documentación y usar Intruder para encontrar posibles archivos ocultos.

---


