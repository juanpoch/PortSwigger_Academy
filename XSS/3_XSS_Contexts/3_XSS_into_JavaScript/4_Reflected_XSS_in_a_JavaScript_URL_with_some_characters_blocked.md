# Lab: Reflected XSS in a JavaScript URL with some characters blocked

This lab reflects your input in a JavaScript URL, but all is not as it seems. This initially seems like a trivial challenge; however, the application is blocking some characters in an attempt to prevent XSS attacks.

To solve the lab, perform a cross-site scripting attack that calls the `alert` function with the string `1337` contained somewhere in the `alert` message.

![Expert](https://img.shields.io/badge/Level-Expert-800080?style=for-the-badge&logo=flask)

---

Nos encontramos con una sección de comentarios, observamos el parametro `postId` en el `DOM`:
![image](https://github.com/user-attachments/assets/8702a9dd-f1d1-415f-b1c6-ec03faabfd15)

Explicación detallada del payload:

`Payload`:
```js
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
    ```js
    {
    method: 'post',
    body: '/post%3fpostId%3d4'
    }
    ```
  Se envía un POST a `/analytics` con el cuerpo `/post?postId=4`
  
  Esto probablemente es una especie de "tracking" de navegación. O sea, le dice al servidor que el usuario está 
  regresando desde el post con ID 4.
  
  Y luego redirige al usuario a la página principal del blog (/) al hacer click en "back to blog":
  ```js
  finally(_ => window.location = '/')">Back to Blog</a>
  ```

🛠️ `.then()`, `.catch()`, `.finally()`   

Son formas de manejar el resultado de `fetch()`:  

`.then()` → si la petición funciona  

`.catch()` → si hubo un error  

`.finally()` → se ejecuta siempre, haya salido bien o mal.    

---

La lógica detrás de esta inyección consiste en cerrar el parámetro actual e insertar nuevos parámetros dentro de la función `fetch` para ejecutar código, aquí es donde entra la cadena `&'}`.

Luego ingresamos nuevos parámetros separados por `,`, `x=x=>{throw/**/onerror=alert,1337}`, `toString=x`, `window+''` y `{x:`:
```js
x=x=>{throw/**/onerror=alert,1337},toString=x,window+'' ,{x:'
```

### ¿Pero la función fetch no tiene solo 2 argumentos?
Correcto: `fetch(input, init)` solo acepta dos argumentos. Entonces, ¿cómo puede funcionar esta inyección si agregamos más?

Probemos con una función simple para entenderlo:
```html
<script>
  function myFunc(a, b){
    return a + b;
    }
  console.log(myFunc(1,2));
</script>
```
Resultado:
```html
3
```
Ahora intentamos pasarle más parámetros de los que espera:
```html
<script>
  function myFunc(a, b){
    return a + b;
    }
  console.log(myFunc(1, 2, 3));
</script>
```
Resultado:
```html
3
```
No se lanza ningún error, incluso si agregamos argumentos adicionales. Simplemente son ignorados por la función.

Ahora veamos qué pasa si aprovechamos esos argumentos adicionales para ejecutar código:
```html
<script>
  let myVar = 1;
  function myFunc(a, b){
    return a + b;
    }
  console.log(myFunc(1, 2, myVar=10, 4));
  console.log(myVar);
</script>
```
Resultado:
```html
3
10
```
✅ Aunque `myFunc` no usa esos parámetros extra, su simple evaluación modifica el valor de una variable global.  

✅ Conclusión:  

Sí, podemos agregar parámetros dentro de una inyección aunque la función `fetch` no los use. JavaScript los evalúa igualmente, y podemos aprovechar esto para ejecutar código malicioso.


---

### Primer parámetro inyectado:
-  `x=x=>{throw/**/onerror=alert,1337}`:

En este caso estamos definiendo una función flecha con un parámetro `x`, el cual no estamos utilizando en esta función, el motivo simplemente es la necesidad de declarar una función sin el uso de determinados caracteres que están siendo filtrados por el WAF, como los paréntesis `()`.

La función `x()` se definiría así de forma tradicional:
```js
function x(x) {
  throw onerror=alert, 1337;
}
```
o 
```js
let x = function(x) {
  throw onerror=alert, 1337;
};
```
`Explicación throw`:
Nosotros sabemos que `throw 1337` lanza una excepción con el número `1337`. Al no haber un `try...catch` que capture la excepción, se fuerza un error sin capturar.

- Si nosotros ejecutamos `throw 1337, 1338`, el navegador lanzará una excepción y retornará el último valor de la lista de valores separados por coma.
Qué pasa con los valores anteriores:
```html
<script>
  let myVar = 1;
  throw myVar= 1337, myVar;
</script>
```
En este caso se lanzará un error con un valor 1337. Esto quiere decir que podemos ejecutar código en todos los valores de la lista separada por comas que brindamos, ya que pudimos sobreescribir el valor de `myVar`. Cabe destacar que podemos agregar tantos valores como querramos dentro de esta lista, por lo que podríamos también hacer lo siguiente:
```html
<script>
  throw onerror=alert, 1338;
</script>
```
En este caso, tenemos el event handler `onerror`, que por defecto maneja los errores no capturados en el navegador.
Lo que estamos haciendo es sobrescribir su comportamiento por defecto asignándole la función `alert`.

De esta manera, cuando ocurra un error no capturado, en lugar de realizar el manejo estándar, se ejecutará `alert`.

Luego, forzamos un error usando `throw`, lo cual activa el `onerror` y, por lo tanto, se ejecuta `alert` automáticamente.  

`Nota`: Cuando no se sobrescribe (`onerror = ...`), el comportamiento por defecto de `window.onerror` es simplemente mostrar el error en la consola del navegador.

Por lo tanto nosotros estamos usando la siguiente función flecha, que es equivalente a las funciones anteriores:
```js
x=x=>{throw/**/onerror=alert,1337}
```
Por definición, esta es una función flecha llamada `x`, que tiene un parámetro `x` (que no usaremos), que ejecuta el código `throw/**/onerror=alert,1337`. Que ya se explicó a detalle qué función cumple. En el caso de este lab, se necesita "spoofear" el caracter espacio ` `, por lo que se utiliza el comentario vacío `/**/` con tal finalidad.

`Nota`: Este parámetro se encargará simplemente de declarar la función `x()`. Para poder ejecutar una función, hay que llamarla. Para eso utilizaremos el método de sobreescribir la función `toString` con la función `x()` e intentar que JavaScript la ejecute a través de forzar la concatenación del objeto `window` con una cadena vacía `''` (de esto se encargan los siguientes parámetros).

----

### Segundo parámetro inyectado en la `API fetch`:  

- `toString = x`: Aquí estamos sobrescribiendo el método `toString`, que normalmente convierte objetos a cadenas de texto. En este caso, lo reemplazamos con la función `x()` definida anteriormente. Más adelante, cuando forcemos la conversión de un objeto a string, se ejecutará esta función en lugar del comportamiento por defecto.

### ¿Por qué `toString = x` modificará `window.toString`?  

Porque en el contexto global del navegador, las variables globales (como `toString`) se asignan automáticamente como propiedades del objeto global `window`. Es decir, `toString = x` es equivalente a `window.toString = x`.

Esto es importante porque luego vamos a forzar la conversión del objeto `window` a cadena, con `window + ''`, lo que activará nuestro `toString()` personalizado y ejecutará el código malicioso.

---

Tercer parámetro inyectado en la `API fetch`:  

- `window+''`:  Este es el intento de realizar una concatenación entre el objeto `window` y una cadena vacía `''`.
 Cuando se utiliza el operador `+` junto con una cadena vacía (`''`), JavaScript realiza una coerción de tipo e intenta convertir el otro valor a una cadena. Para objetos como `window`, esto implica llamar al método `toString()` definido en ese objeto. Si `toString` ha sido sobrescrito, se ejecutará la nueva versión definida.
Aquí es donde se ejecuta nuestra función `x()` y logramos ejecutar código.

`Nota`: En JavaScript, `window` es el objeto global que representa la ventana del navegador. Contiene todos los objetos, funciones y variables globales disponibles en una página web. Por ejemplo, funciones como `alert()`, `setTimeout()` o el objeto `document` están accesibles a través de `window`.
Ejemplo:
```js
window.alert("Hola"); // Es lo mismo que alert("Hola")
```
También es donde ocurren eventos globales como `onerror`, y se pueden sobrescribir propiedades para modificar el comportamiento de la página.

---

- Ultimo parámetro inyectado en la `API fetch`:
  - `,{x:'`:
 
  Hasta ahora la función fetch quedaría así:
  ```js
  fetch('/analytics', {method:'post',body:'/post?postId=4&'}, ..arg1.., ..arg2.., window+'''})
  ```

Vemos que en la sentencia, nos queda una cadena de caracteres que causarían un error: `'})`.

Por eso agregamos un argumento más, el argumento `{x:''}` (agregando `,{x:'` y aprovechando las últimas `'}` suelta:
```js
arg3,{x:''}
```
La sentencia final quedaría así:
```js
fetch('/analytics', {method:'post',body:'/post?postId=4&'}, ..arg1.., ..arg2.., window+'',{x:''})
```
`Nota`: El elemento `{x:''}` es ...













    








