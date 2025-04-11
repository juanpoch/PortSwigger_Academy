# Lab: Reflected XSS in a JavaScript URL with some characters blocked

This lab reflects your input in a JavaScript URL, but all is not as it seems. This initially seems like a trivial challenge; however, the application is blocking some characters in an attempt to prevent XSS attacks.

To solve the lab, perform a cross-site scripting attack that calls the `alert` function with the string `1337` contained somewhere in the `alert` message.

![Expert](https://img.shields.io/badge/Level-Expert-800080?style=for-the-badge&logo=flask)

---

Nos encontramos con una sección de comentarios, observamos el parametro `postId` en el `DOM`:
![image](https://github.com/user-attachments/assets/8702a9dd-f1d1-415f-b1c6-ec03faabfd15)

Explicación detallada del payload:

`Payload`:
```html
/post?postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27
```

Nosotros sabemos que el parámetro `postId` se inserta dentro de la siguiente función fetch:
```html
<a href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d4'}).finally(_ => window.location = '/')">Back to Blog</a>
```
Este es un enlace `<a>` que ejecuta JavaScript cuando el usuario hace clic. Específicamente, ese código está usando la API `fetch()` para hacer una petición HTTP.

- `href="javascript:..."`:
  Este tipo de enlace no navega a otra URL tradicional, sino que ejecuta código JavaScript directamente cuando lo clickeás, en este caso está ejecutando la función `fetch`.

 La función `fetch()` es parte del API moderna de JavaScript para hacer peticiones HTTP desde el navegador — sin 
 necesidad de recargar la página.

 Permite que tu JavaScript se comunique con servidores para:
 - Obtener datos (como JSON, HTML, texto, imágenes...)
 - Enviar información (como formularios, eventos, analíticas...)
 - Hacer APIs dinámicas o apps de una sola página (SPA)


- `fetch('/analytics', {method:'post', body: '/post%3fpostId%3d4'})`:
  
  Aquí es donde ocurre el envío de una petición `POST`. La función `fetch` tiene 2 parámetros:
  - `fetch('/analytics', ...)`:
    Esto hace una solicitud HTTP a la URL `/analytics`.
  - El segundo parámetro, opciones de fetch:
    ```html
    {
    method: 'post',
    body: '/post%3fpostId%3d4'
    }
    ```
  Se envía un POST a `/analytics` con el cuerpo `/post?postId=4`
  Esto probablemente es una especie de "tracking" de navegación. O sea, le dice al servidor que el usuario está 
  regresando desde el post con ID 4.
  Y luego redirige al usuario a la página principal del blog (/) al hacer click en "back to blog":
  ```html
  finally(_ => window.location = '/')">Back to Blog</a>
  ```

🛠️ `.then()`, `.catch()`, `.finally()` 
Son formas de manejar el resultado de `fetch()`:
`.then()` → si la petición funciona
`.catch()` → si hubo un error
`.finally()` → se ejecuta siempre, haya salido bien o mal.




    








