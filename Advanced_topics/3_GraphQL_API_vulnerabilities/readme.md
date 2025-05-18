# GraphQL API Vulnerabilities

Esta guía explora las vulnerabilidades comunes que pueden encontrarse al auditar APIs GraphQL. Incluye desde el descubrimiento de endpoints y el abuso de introspección hasta vulnerabilidades como IDOR, CSRF y filtrado de datos.

---

## 🔍 Qué es GraphQL?

GraphQL es un lenguaje de consulta de APIs desarrollado por Facebook, que permite a los clientes especificar exactamente los datos que necesitan. A diferencia de REST, GraphQL utiliza un **único endpoint** para todas las operaciones (queries, mutations y subscriptions).

> En seguridad, esto representa una superficie de ataque altamente estructurada, pero centralizada.

---

## 🎯 Vulnerabilidades comunes en GraphQL

| Tipo | Descripción |
|------|-------------|
| Introspection Enabled | Permite al atacante consultar el esquema completo. |
| IDOR | El atacante accede a objetos para los que no tiene permisos. |
| CSRF via GET | Algunas APIs aceptan consultas GET sin protección. |
| Suggestion Leaks | El servidor sugiere nombres de campos, filtrando partes del esquema. |
| Verbose Errors | Errores detallados ayudan a descubrir la estructura interna. |
| Injection in Arguments | Puede permitir inyecciones si los argumentos no son sanitizados. |

---

## 🚩 Descubrimiento del endpoint GraphQL

### 📌 Universal Query

Enviás la siguiente consulta:

```graphql
query { __typename }
```

Si recibís una respuesta como:
```json
{"data": {"__typename": "query"}}
```
Entonces estás frente a un endpoint GraphQL válido.

### 📂 Endpoints comunes a testear:

- `/graphql`
- `/api/graphql`
- `/graphql/api`
- `/graphql/graphql`
- `/api`
- `/v1/graphql`

`Nota`: Los servicios GraphQL suelen responder a cualquier solicitud no GraphQL con un error de "query not present" o similar. Tenga esto en cuenta al realizar pruebas con endpoints GraphQL.

### 🧪 Métodos HTTP

- `POST` con `Content-Type: application/json` es el estándar.
- Algunos endpoints aceptan `GET` o `POST` con `x-www-form-urlencoded` ➜ potencial CSRF.

---

## 🔬 Primera fase: pruebas iniciales

1. Usar Burp Suite con el navegador integrado.
2. Interactuar con la web y capturar las queries.
3. Explorar el histórico HTTP en busca de estructuras GraphQL.

---

## 🕵️‍♂️ Exploración del esquema: Introspection

### ✍️ Probing:
```json
{"query": "{__schema{queryType{name}}}"}
```

Si está habilitado, devuelve nombres de queries disponibles.

### 📜 Query completa de introspección:
Usá la query `IntrospectionQuery` (ver al final del documento) para descubrir:
- Tipos
- Queries
- Mutations
- Subscriptions
- Fragmentos y directivas

> Burp puede generar introspección automáticamente desde Repeater (menú contextual).

### 🧭 Herramientas recomendadas:
- [GraphQL Voyager](https://apis.guru/graphql-voyager/) para visualizar el esquema
- [Clairvoyance](https://github.com/nikitastupin/clairvoyance) para recuperar el esquema sin introspección

---

## 🧨 Explotación de argumentos no sanitizados (IDOR)

Si una consulta expone objetos por ID:

```graphql
query {
  product(id: 3) {
    id
    name
    listed
  }
}
```

Y el usuario puede alterar ese ID, puede explotar un **Insecure Direct Object Reference** si no hay control de acceso.

---

## 🧠 Detección basada en sugerencias (Apollo)

GraphQL sobre Apollo puede mostrar sugerencias si escribís mal una consulta:

```graphql
query {
  productInfo
}
```

Podría responder:
```json
"Did you mean 'productInformation'?"
```
Esto filtra parte del esquema. Burp Scanner detecta esto como **"GraphQL suggestions enabled"**.

---

## 🧱 Protecciones recomendadas para entornos productivos

- 🔒 Desactivar introspección (`introspection: false` en Apollo Server).
- 🚫 Evitar sugerencias (workaround disponible en GitHub).
- ✅ Validar roles/ACL antes de devolver objetos sensibles.
- ⚠️ Limitar profundidad de queries y complejidad.
- 📌 Activar límites de tasa por IP (rate-limiting).

---

## 🔗 Recursos adicionales

- [What is GraphQL? - PortSwigger](https://portswigger.net/web-security/graphql)
- [Working with GraphQL in Burp Suite](https://portswigger.net/burp/documentation/guided/getting-started/graphql)
- [Clairvoyance - Github](https://github.com/nikitastupin/clairvoyance)

---

## 📌 Fragmento completo de introspección
> → Si lo necesitás, podés ver la versión expandida [aquí](https://graphql.org/learn/introspection/) o usar directamente Burp para generar la query.

> ⚠️ Si falla, eliminá `onOperation`, `onField` y `onFragment`, ya que muchas APIs no lo permiten.

---

[Lab: Accessing private GraphQL posts](1_Accessing_private_GraphQL_posts.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 
