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

---

La lógica detrás de esta inyección consiste en cerrar el parámetro actual e insertar nuevos parámetros dentro de la función `fetch` para ejecutar código,.aquí es donde entra la cadena `&'}`.

Luego ingresamos nuevos parámetros separados por `,`:
```html
x=x=>{throw/**/onerror=alert,1337},toString=x,window+'' ,{x:'
```

- `x=x=>{throw/**/onerror=alert,1337}`:

En este caso estamos definiendo una función flecha con un parámetro `x`, el cual no estamos utilizando en esta función, el motivo simplemente es la necesidad de declarar una función sin el uso de determinados caracteres que están siendo filtrados por el WAF, como los paréntesis `()`.

La función `x()` se definiría así de forma tradicional:
```javascript
function x(x) {
  throw onerror=alert, 1337;
}
```
o 
```javascript
let x = function(x) {
  throw onerror=alert, 1337;
};
```
`Explicación throw`:
Nosotros sabemos que `throw 1337` lanza una excepción con el número `1337`. Al no haber un `try...catch` que capture la excepción, se fuerza un error sin capturar.

- Si nosotros ejecutamos `throw 1337, 1338`, el navegador lanzará una excepción y retornará el último valor de la lista de valores separados por coma.
Qué pasa con los valores anteriores:
```javascript
<script>
  let myVar = 1;
  throw myVar= 1337, myVar;
</script>
```
En este caso se lanzará un error con un valor 1337. Esto quiere decir que podemos ejecutar código en todos los valores de la lista separada por comas que brindamos, ya que pudimos sobreescribir el valor de `myVar`. Cabe destacar que podemos agregar tantos valores como querramos dentro de esta lista, por lo que podríamos también hacer lo siguiente:
```javascript
<script>
  throw onerror=alert, 1338;
</script>
```
En este caso, tenemos el event handler `onerror`, que por defecto maneja los errores no capturados en el navegador.
Lo que estamos haciendo es sobrescribir su comportamiento por defecto asignándole la función `alert`.

De esta manera, cuando ocurra un error no capturado, en lugar de realizar el manejo estándar, se ejecutará `alert`.

Luego, forzamos un error usando `throw`, lo cual activa el `onerror` y, por lo tanto, se ejecuta `alert` automáticamente.










    








