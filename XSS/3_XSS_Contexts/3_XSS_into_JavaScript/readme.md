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

## 🪓 Paso a paso: qué hace este payload

### `</script>`:
- Cierra de forma anticipada la etiqueta `<script>` actual.
- Esto rompe el bloque de JavaScript donde estaba la variable `input`.

### `<img src=1 onerror=alert(document.domain)>`:
- Inyecta un elemento HTML (una imagen).
- Le agrega el atributo `onerror`, que es un *event handler*.
- Cuando el navegador no puede cargar la imagen (porque `src=1` no es válido), se dispara el evento `onerror`, que ejecuta `alert(document.domain)`.

---

## ⚙️ ¿Por qué funciona si "rompe" el script anterior?

Porque los navegadores:

1. Primero parsean el **HTML**, y cuando encuentran etiquetas `<script>`, almacenan el código JavaScript.
2. Cuando vos "rompés" la etiqueta `</script>`, el navegador **cierra el script actual** y sigue procesando HTML.
3. Entonces el navegador simplemente interpreta tu `<img>` como parte del HTML, y ejecuta su evento `onerror`.

> Aunque la línea JS `var input = '` queda rota, eso **no bloquea** que se siga procesando lo demás.  
> No todo el archivo HTML se invalida.


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


