# DOM-based XSS

# ¿Qué es el DOM-based XSS?

El DOM-based XSS es un tipo de vulnerabilidad que ocurre cuando el código JavaScript del lado del cliente (es decir, que se ejecuta en el navegador) toma datos controlados por el atacante —como partes de la URL— y los inserta en funciones inseguras (llamadas *sinks*), como `eval()` o `innerHTML`, que permiten la ejecución de código.

Esto le da al atacante la posibilidad de ejecutar JavaScript malicioso directamente en el navegador de la víctima, lo que puede llevar al robo de información sensible como cookies, tokens de sesión u otros datos personales.

A diferencia de los ataques XSS tradicionales, el DOM-based XSS no depende de una respuesta vulnerable del servidor. Todo ocurre en el navegador, donde el contenido del DOM se modifica dinámicamente sin interacción con el servidor.

---

## ¿Qué es el DOM?

El **DOM** (Document Object Model) es una **representación en memoria** de la estructura de una página web. Cuando el navegador carga una página HTML, convierte ese contenido en un modelo de objetos que organiza los elementos del sitio como un **árbol jerárquico**. Cada nodo del árbol representa una parte del documento: etiquetas HTML (`<div>`, `<p>`, `<a>`, etc.), atributos (`id`, `class`, etc.), y texto.

Gracias al DOM, JavaScript puede:

- Leer y modificar el contenido de un elemento.
- Agregar o eliminar elementos de la página.
- Cambiar atributos de los elementos.
- Reaccionar a eventos como clics del usuario, presionar teclas, etc.

> Este modelo dinámico permite que una página web no sea simplemente algo estático, sino que pueda adaptarse y responder en tiempo real a lo que hace el usuario.

Por ejemplo, si tenés un HTML como este:

```html
<p id="mensaje">Hola, mundo</p>
```

Podés cambiar el texto con JavaScript usando el DOM:

```javascript
document.getElementById("mensaje").innerText = "¡Hola, usuario!";
```

---

## ¿Qué hace JavaScript del lado del cliente?

JavaScript del lado del cliente es el que se ejecuta directamente en el navegador del usuario. Sirve principalmente para interactuar con el DOM, responder a eventos (como clics o teclas), validar formularios, hacer animaciones o solicitudes a servidores mediante AJAX, entre otras cosas.

Este código puede estar:

- Escrito dentro de etiquetas `<script>` directamente en el HTML.
- Referenciado desde archivos externos, por ejemplo: `<script src="script.js"></script>`.

---

## ¿A qué se refiere con "código JavaScript del lado del cliente"?

Se refiere a cualquier código JavaScript que corre en el navegador (no en el servidor), y que tiene acceso al contenido de la página (DOM), al almacenamiento local, a cookies, a la URL, etc. Este código es visible para el usuario si inspecciona la página con herramientas de desarrollo (como F12 en Chrome) o si revisa el código fuente.

---

## Ejemplo de DOM-based XSS vulnerable

Supongamos que tenemos la siguiente página HTML:

```html
<!DOCTYPE html>
<html>
  <body>
    <p id="output"></p>
    <script>
      var name = new URLSearchParams(window.location.search).get("name");
      document.getElementById("output").innerHTML = name;
    </script>
  </body>
</html>
```

Esta página toma el parámetro `name` de la URL y lo inserta directamente en el HTML usando `innerHTML`. Este ejemplo se explicará detalladamente más adelante.

`Nota`: El navegador descarga el HTML original del servidor y lo muestra tal cual en "Ver código fuente". Ese contenido no cambia, ni siquiera si JavaScript lo modifica más tarde. Quiere decir, que lo que está modificando realmente es el DOM, el cual se visualiza con las "dev tools".

Un atacante podría enviar este enlace a una víctima:

```
http://vulnerable.com/page.html?name=<img src=x onerror="alert('XSS')">
```

Cuando la víctima abra ese enlace, se ejecutará el código JavaScript malicioso (`alert('XSS')`).


---

## ¿Cómo identificar un DOM-based XSS?

Para explotar este tipo de vulnerabilidad, el atacante debe ubicar datos en una fuente (*source*) que luego sean procesados por un *sink* vulnerable. La fuente más común es la URL, accedida con `window.location`, `document.URL`, `location.search`, `location.hash`, etc.

### Ejemplo básico:

```javascript
// Código vulnerable
var name = new URLSearchParams(window.location.search).get("name");
document.getElementById("output").innerHTML = name;
```

#### Explicación
Procedemos a explicar paso a paso el ejemplo original:  

`window.location.search`: Esto accede a la parte de la URL que contiene los parámetros (la query string). Por ejemplo:
```
https://example.com/index.html?name=Juan
```
En este caso devuelve `?name=Juan`.  

`new URLSearchParams(...)`: Esto convierte la query string en un objeto para poder acceder fácilmente a los valores de cada parámetro.
Esto permite hacer:  

```js
.get("name")  // devuelve "Juan"
```
`document.getElementById("output").innerHTML = name;`: Este paso inserta el valor directamente en el HTML (DOM) de la página, en el elemento con `id="output"`.
Si el html fuera:  

```js
<div id="output"></div>
```
Se convertiría en:  

```js
<div id="output">Juan</div>
```
`Nota`: `innerHTML` es una propiedad de los elementos del DOM que te permite leer o escribir contenido HTML dentro de un elemento.  

Por lo tanto, el HTML original descargado por el navegador seguiría siendo el mismo:
```js
<!DOCTYPE html>
<html>
  <body>
    <p id="output"></p>
    <script>
      var name = new URLSearchParams(window.location.search).get("name");
      document.getElementById("output").innerHTML = name;
    </script>
  </body>
</html>
```
🔸 El <p> está vacío porque en el archivo original no hay contenido cargado aún. JavaScript no se ha ejecutado todavía cuando ves el "código fuente".
En cambio el DOM sería el siguiente:
```js
<!DOCTYPE html>
<html>
  <body>
    <p id="output">Juan</p>
    <script>
      var name = new URLSearchParams(window.location.search).get("name");
      document.getElementById("output").innerHTML = name;
    </script>
  </body>
</html>
```
🔸 Ahora el contenido del <p> fue modificado por JavaScript: se insertó "Juan" directamente en el DOM.

Ejemplos de operaciones con `innerHTML`:  

🔹 `Ejemplo 1`: Leer contenido con innerHTML  

HTML:
```js
<div id="demo"><b>Hola</b> mundo</div>
```
JavaScript:
```js
var contenido = document.getElementById("demo").innerHTML;
console.log(contenido);  // Muestra: <b>Hola</b> mundo
```
🔹 `Ejemplo 2`: Escribir contenido con innerHTML
HTML:
```js
<div id="demo"></div>
```
JavaScript:
```js
document.getElementById("demo").innerHTML = "<p>Hola <b>mundo</b></p>";
```
Resultado:
```js
<div id="demo">
  <p>Hola <b>mundo</b></p>
</div>
```

Por lo tanto si el usuario accede a:
```
https://example.com/page.html?name=<img src=x onerror=alert(1)>
```

Se ejecutará JavaScript malicioso porque `innerHTML` permite la inserción de HTML y ejecución de eventos como `onerror`.

---

## Cómo probar manualmente un DOM-based XSS

### 1. **Pruebas en sinks HTML**  
Coloca una cadena única en la fuente, como `?input=abc123`, y busca esa cadena en el DOM usando las herramientas para desarrolladores de Chrome (`Ctrl + F` en el panel Elements). Si la cadena aparece dentro del DOM, intenta inyectar caracteres especiales para romper la sintaxis y ejecutar código.

Ejemplo:
```
?input="><script>alert(1)</script>
```

### 2. **Pruebas en sinks de ejecución JS**  
Utiliza el depurador JavaScript en Chrome (`Ctrl + Shift + F`) para buscar referencias a `location`, `document.URL`, etc. Luego añade puntos de interrupción (breakpoints) y sigue cómo se manipula esa variable. Si ves que el valor fluye hacia funciones como `eval()`, `setTimeout()`, `Function()`, puede ser explotable.

---

## Herramientas: DOM Invader

Burp Suite cuenta con una extensión llamada **DOM Invader** integrada en su navegador Burp. Esta herramienta automatiza parte del proceso de detección y explotación de DOM XSS, marcando fuentes y sinks automáticamente.

[Documentación de DOM Invader - PortSwigger](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)


---

## Ejemplos de sinks comunes

### 1. `document.write()`
```javascript
document.write("<script>alert(document.domain)</script>");
```

### 2. `element.innerHTML`
```javascript
element.innerHTML = '<img src=1 onerror=alert(document.domain)>';
```

> ⚠️ `innerHTML` ya no permite etiquetas `<script>`, pero sí otros elementos como `<img>` con eventos (`onerror`, `onload`).

---

## DOM XSS en librerías como jQuery

### jQuery.attr()

```javascript
$('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnUrl'));
```

Payload malicioso:
```
?returnUrl=javascript:alert(document.domain)
```

### jQuery + `location.hash`:

```javascript
$(window).on('hashchange', function() {
    var element = $(location.hash);
    element[0].scrollIntoView();
});
```

Exploit:
```html
<iframe src="https://vulnerable-site.com#" onload="this.src+='<img src=1 onerror=alert(1)>'"></iframe>
```

---

## DOM XSS en AngularJS

Cuando se usa AngularJS con `ng-app`, es posible ejecutar JavaScript usando dobles llaves:

```html
<div ng-app>
    {{constructor.constructor('alert(1)')()}}
</div>
```

---

## DOM XSS reflejado y almacenado

### Reflejado:
El servidor refleja parámetros en la respuesta HTML y un script los procesa en un *sink*.

```javascript
eval('var data = "' + location.search + '"');
```

### Almacenado:
El servidor guarda información en una base de datos que luego es procesada por el cliente.

```javascript
element.innerHTML = comment.author;
```

---

## Sinks comunes que pueden generar DOM-XSS

### Nativos:
- `document.write()`
- `document.writeln()`
- `element.innerHTML`
- `element.outerHTML`
- `element.insertAdjacentHTML`
- `element.onevent` (como `onclick`, `onerror`, etc.)

### jQuery:
- `html()`, `append()`, `prepend()`, `after()`, `before()`
- `wrap()`, `wrapInner()`, `wrapAll()`
- `replaceWith()`, `replaceAll()`
- `$()`, `add()`, `animate()`
- `jQuery.parseHTML()`, `$.parseHTML()`

---

## Cómo prevenir DOM-based XSS

- **Evitar usar sinks peligrosos** como `innerHTML`, `eval()`, `document.write()` con datos no confiables.
- **Sanitizar la entrada del usuario** antes de incluirla en el DOM.
- **Utilizar APIs seguras**, como `textContent` en lugar de `innerHTML`.
- **Utilizar frameworks modernos** que escapan automáticamente el contenido.
- **Auditar librerías de terceros** que puedan tener sinks vulnerables.

---

## Conclusión

El DOM-based XSS es una vulnerabilidad peligrosa y muchas veces difícil de detectar, ya que ocurre completamente en el navegador del cliente. Su explotación requiere entender cómo fluye la información desde las fuentes hasta los sinks, y cómo el código JavaScript del sitio manipula dicha información. Las buenas prácticas de desarrollo y el uso de herramientas de auditoría pueden prevenir su aparición.
