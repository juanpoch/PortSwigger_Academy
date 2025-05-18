# 📘 Guía Conceptual GraphQL
GraphQL es un lenguaje de consulta para APIs desarrollado por Facebook que permite a los clientes **especificar exactamente los datos que necesitan**, reduciendo el número de llamadas a la API y evitando respuestas innecesariamente grandes.

> GraphQL se basa en un único endpoint para todas las operaciones: consultas, mutaciones y suscripciones.

---

## 🤖 Funcionamiento general de GraphQL

- Todas las peticiones se envían a **un solo endpoint** (generalmente vía POST).
- Los clientes especifican la estructura de la respuesta deseada.
- El servidor responde con un **JSON** estructurado según esa solicitud.

### Operaciones principales:

| Tipo        | Equivalente REST       | Descripción                                      |
|-------------|-------------------------|--------------------------------------------------|
| `query`     | GET                     | Recupera datos                                   |
| `mutation`  | POST/PUT/DELETE         | Modifica datos (crear, actualizar, eliminar)     |
| `subscription` | WebSocket              | Mantiene una conexión para recibir cambios en tiempo real |

---

## 📋 Esquemas GraphQL

Un **esquema** define la estructura de los datos disponibles: tipos, campos, argumentos y relaciones. Es el contrato entre frontend y backend.

### Ejemplo:
```graphql
type Product {
  id: ID!
  name: String!
  description: String!
  price: Int
}
```

> El operador `!` indica que el campo es obligatorio (non-null).

---

## 🔍 Consultas GraphQL

Las consultas (`query`) recuperan información. El cliente elige los campos a devolver:

```graphql
query myGetProductQuery {
  getProduct(id: 123) {
    name
    description
  }
}
```

Respuesta:
```json
{
  "data": {
    "getProduct": {
      "name": "Juice Extractor",
      "description": "Kitchen appliance."
    }
  }
}
```

---

## 📉 Mutaciones GraphQL

Las `mutations` sirven para insertar, modificar o eliminar datos:

```graphql
mutation {
  createProduct(name: "Glass", listed: "yes") {
    id
    name
    listed
  }
}
```

Respuesta:
```json
{
  "data": {
    "createProduct": {
      "id": 123,
      "name": "Glass",
      "listed": "yes"
    }
  }
}
```

---

## 🌐 Componentes comunes

### ✅ Campos
En GraphQL, cada tipo de dato (como `Employee`, `Product`, `User`) tiene campos que representan los atributos o propiedades que se pueden consultar o modificar.

Cuando se hace una consulta, se puede elegir exactamente qué campos recibir en la respuesta, y la API los devuelve:
```graphql
query {
  getEmployees {
    id
    name {
      firstname
      lastname
    }
  }
}
```

### ✅ Argumentos
Permiten filtrar resultados:
```graphql
query {
  getEmployees(id: 1) {
    name {
      firstname
      lastname
    }
  }
}
```

### ✅ Variables
Separan datos de la consulta:
```graphql
query getEmployeeWithVariable($id: ID!) {
  getEmployees(id: $id) {
    name {
      firstname
      lastname
    }
  }
}

// Variables:
{
  "id": 1
}
```

### ✅ Alias
Permiten renombrar respuestas para evitar colisiones:
```graphql
query {
  emp1: getEmployees(id: 1) { name }
  emp2: getEmployees(id: 2) { name }
}
```

### ✅ Fragmentos
Fragmentos reutilizables de campos:
```graphql
fragment productInfo on Product {
  id
  name
  listed
}

query {
  getProduct(id: 1) {
    ...productInfo
    stock
  }
}
```

---

## 🔔 Suscripciones

Las `subscription` permiten recibir actualizaciones en tiempo real (ej: chats, precios en vivo). Suelen implementarse con **WebSockets**.

---

## 🤯 Introspección

Permite consultar la estructura del esquema:
```graphql
query {
  __schema {
    types { name }
  }
}
```

> ⚠ Puede usarse para descubrir campos sensibles. Debe desactivarse en entornos productivos.

---

## ⚠ Riesgos de seguridad asociados

- Uso de argumentos sin control de acceso → **IDOR**
- Introspección habilitada → **disclosure del esquema completo**
- Alias para evadir rate-limiting
- Mutaciones mal validadas → **alteración de datos**

Para detalles técnicos y explotar estas fallas: ver la guía [GraphQL API Vulnerabilities](./graphql_api_vulnerabilities.md)

---

¿Querés que ahora prepare ejercicios prácticos para aplicar estos conceptos desde Burp o desde consola?
