# DOM XSS in jQuery selector sink using a hashchange event

This lab contains a DOM-based cross-site scripting vulnerability on the home page. It uses jQuery's `$()` selector function to auto-scroll to a given post, whose title is passed via the `location.hash` property.

To solve the lab, deliver an exploit to the victim that calls the `print()` function in their browser.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)

---

Tenemos el siguiente website:
![image](https://github.com/user-attachments/assets/28a82381-d411-4af3-91f7-ddbca9a94b8a)

Inspeccionamos el código fuente en búsca de etiquetas `<script>`, vemos jQuery:
![image](https://github.com/user-attachments/assets/8289c049-ecc6-4d68-8922-25521823225a)

# 📜 Explicación detallada del script de hashchange y scroll automático

---

## 🖼️ Contexto

En la captura de pantalla, observamos un fragmento de código que utiliza jQuery para reaccionar a cambios en el hash de la URL (`location.hash`) y hacer scroll automático hacia un elemento específico dentro de la página.

Aquí está el script observado:

```javascript
$(window).on('hashchange', function(){
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
    if (post) post.get(0).scrollIntoView();
});
```

---

## 🔍 Explicación parte por parte

### 1. `$(window).on('hashchange', function(){ ... });`

- `$(window)`: Utiliza jQuery para seleccionar el objeto `window` (la ventana del navegador).
- `.on('hashchange', function(){ ... })`: Asocia un listener al evento `hashchange`. Cada vez que cambia el fragmento `#` en la URL, esta función se ejecuta automáticamente.

### 2. `var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');`

- `window.location.hash`: Obtiene el fragmento hash de la URL (por ejemplo, `#Wellness`).
- `.slice(1)`: Elimina el carácter inicial `#`, dejando solo el texto (por ejemplo, `Wellness`).
- `decodeURIComponent(...)`: Decodifica caracteres especiales de URL como `%20` (espacio).
- `$(`section.blog-list h2:contains(...)`)`:
  - Busca dentro de la sección `blog-list` todos los elementos `h2`.
  - El pseudoselector `:contains(...)` selecciona aquellos `h2` cuyo texto **contiene** el valor proporcionado.

### 3. `if (post) post.get(0).scrollIntoView();`

- `if (post)`: Verifica si se encontró al menos un elemento que coincida.
- `post.get(0)`: Obtiene el primer elemento del resultado jQuery en forma de nodo DOM puro.
- `.scrollIntoView()`: Hace que el navegador desplace automáticamente la página para mostrar ese elemento.

---

## 🎯 ¿Qué hace en conjunto este script?

Cada vez que cambia el hash en la URL:

1. Toma el nuevo valor del hash.
2. Decodifica el texto para caracteres especiales.
3. Busca un elemento `<h2>` dentro de la sección `blog-list` que contenga ese texto.
4. Si encuentra uno, automáticamente realiza un desplazamiento hasta el mismo.

---

## ⚠️ Posibles riesgos de seguridad

Aunque `:contains(...)` en jQuery no interpreta directamente HTML, **este enfoque presenta riesgos**:

- **Control del usuario**: `location.hash` es 100% controlado por el usuario.
- **Selectores dinámicos inseguros**: Construir selectores directamente desde entradas de usuario puede abrir la puerta a vulnerabilidades.
- **Dependencia de otros factores**: Si otras partes del código interactúan con los elementos encontrados de manera insegura (por ejemplo, insertando HTML sin sanitización), podría derivar en un XSS.

---

## 📋 Resumen

| Elemento | Descripción |
|:---------|:------------|
| `$(window).on('hashchange')` | Escucha cambios en el hash de la URL. |
| `window.location.hash.slice(1)` | Extrae el texto del hash sin el `#`. |
| `decodeURIComponent(...)` | Decodifica caracteres especiales de URL. |
| `:contains(...)` | Busca elementos cuyo texto contenga el valor especificado. |
| `scrollIntoView()` | Desplaza la página hacia el elemento encontrado. |

---

## 📌 Conclusión

Este script ofrece una funcionalidad práctica de navegación automática, pero su implementación debe hacerse cuidadosamente para evitar riesgos de seguridad. Es fundamental **validar y sanitizar** cualquier entrada controlada por el usuario antes de usarla para construir selectores o manipular el DOM.

---

Si buscamos una cadena dentro de una etiqueta `h2` en la sección `blog-list`, por ejemplo, la cadena `Perseverance`:
![image](https://github.com/user-attachments/assets/edf07813-a276-4c53-9e04-c3b323a1a240)

Si la añadimos como hashtag, vemos que el script actúa y se realiza un scroll down hacia ese elemento:
![image](https://github.com/user-attachments/assets/c255249a-520e-467b-90df-6d42724c0adf)


---

# 📚 Análisis Completo: Comportamiento de jQuery y Vulnerabilidad DOM-Based XSS

## Introducción

Antes de explotar cualquier vulnerabilidad, considero esencial entender el comportamiento de jQuery al trabajar con selectores. En esta sección analizo cómo actúa jQuery cuando interactúa con selectores normales, no existentes y controlados por el usuario, estableciendo la base conceptual para comprender la vulnerabilidad DOM-Based XSS.

---

# 1. Verificando comportamiento de selectores válidos

Primero quiero entender qué pasa si uso jQuery de forma tradicional, seleccionando un ID existente.

Usamos jQuery para buscar en el DOM todos los elementos `h2` que:

- Estén dentro de un section con clase `blog-list`

- Y que su contenido de texto contenga exactamente la cadena "The Peopleless Circus"
![image](https://github.com/user-attachments/assets/3deb4309-99b0-4c3f-82a8-f5327b6a66fc)

La consola devuelve un objeto jQuery.

Ese objeto tiene:

- 0: h2 ➔ El primer (y único) elemento que cumple con ese criterio: un `<h2>`.

- selector ➔ `"section.blog-list h2:contains(The Peopleless Circus)"`, el mismo que escribimos.

- length: 1 ➔ Hay exactamente un solo match encontrado.

- context ➔ Muestra que el contexto de búsqueda es el `HTMLDocument` actual.

- prevObject ➔ Hace referencia al estado anterior de la búsqueda en jQuery (algo interno de jQuery, no importante para la explotación).

### Conclusión:
✅ Encontramos un `<h2>` dentro de `section.blog-list` cuyo texto contiene `"The Peopleless Circus"`.

✅ jQuery devuelve una **colección** con ese único elemento (`length: 1`).

✅ No creamos nuevos elementos, simplemente estamos **seleccionando un nodo existente en el DOM**.


## Declaración de variable y asignación del selector

En este paso, declaramos una variable `post` y guardamos en ella el resultado de una búsqueda jQuery:

```javascript
var post = $('section.blog-list h2:contains(The Peopleless Circus)');
```

**Captura de la operación:**

![image](https://github.com/user-attachments/assets/0a7fd444-6711-404e-92cf-aa07c5771fbe)



✅ Declaramos una variable `post` y guardamos en ella el resultado de un selector jQuery.

✅ El selector busca un `<h2>` que contenga el texto `"The Peopleless Circus"`.

✅ La consola muestra `undefined` porque una asignación no tiene valor de retorno.

✅ La variable `post` ahora contiene una **colección jQuery** con el elemento encontrado.

---

### ¿Por qué la consola muestra `undefined`?

Cuando en la consola ejecutamos una asignación como:

```javascript
var post = $('section.blog-list h2:contains(The Peopleless Circus)');
```

el resultado de la operación `var` es `undefined`.  
Esto es el comportamiento normal de JavaScript: **declarar una variable no devuelve nada visible** en la consola.

---

⚡️ **Importante**:

- No significa que `post` esté vacío o mal asignado.
- Simplemente la consola muestra `undefined` porque la operación de asignar algo a una variable no tiene un valor de retorno.

---


---


```javascript
$('#post')
```

- Si el elemento con ID `post` existe en el DOM, jQuery me devuelve una **colección** con ese elemento.
- No hay problemas: todo funciona como debería.

Ahora, si intento acceder al primer elemento directamente:

```javascript
$('#post')[0]
```

- Me devuelve el **elemento DOM real** (por ejemplo, `<div id="post"></div>` si existiera).

📌 **Observación**:
- `$()` devuelve una **colección jQuery**, pero `[0]` me da el **elemento DOM puro**.

---

# 2. Qué pasa cuando el ID no existe

Ahora pruebo qué ocurre si el ID **no existe**:

```javascript
$('#nonexistent')
```

- jQuery me devuelve una **colección vacía**.

Y si intento acceder al primer elemento:

```javascript
$('#nonexistent')[0]
```

- Obtengo **undefined**.

🛡️ **Nota importante**:
- Si paso un ID que no existe, **no hay errores**, simplemente jQuery devuelve vacío.
- No se crean elementos. **No hay manipulación del DOM**.

⚡ **Advertencia**:
- Es normal que `[0]` sea `undefined` si no se encontró el ID.

---

# 3. Analizando entrada controlada: HTML en lugar de ID

Ahora me pregunto: ¿qué sucede si, en lugar de pasar un simple ID como `#post`, paso algo que parece HTML?

Por ejemplo:

```javascript
$('<img src=x onerror=alert(1)>')
```

¿Qué hace jQuery?

- En versiones antiguas (pre 3.0), **detecta que empieza con `<`** y lo **interpreta como HTML**, no como un selector.
- **Crea un elemento** real en memoria: un `<img>` con un evento `onerror`.

📌 **Observación**:
- jQuery **parsea la entrada** y **genera nodos reales** si ve un fragmento HTML.

🛡️ **Nota importante**:
- Este comportamiento es completamente automático si se usan versiones antiguas de jQuery.
- En versiones recientes (>=3.0), este comportamiento fue cambiado para evitar problemas de seguridad.

---

# 4. Explorando un selector con contains()

También puedo utilizar selectores avanzados. Por ejemplo:

```javascript
$('section.blog-list h2:contains(Wellness)')
```

Este selector busca todos los elementos `h2` dentro de `section.blog-list` que **contengan el texto** "Wellness".

**Captura del resultado en la consola:**

![Captura de consola mostrando un match](../7bf4abf0-6188-4d0c-a90d-1d54f17ec146.png)

- Se observa que surge un **match**, es decir, se encuentra un elemento `h2` que contiene "Wellness".
- jQuery devuelve una colección que contiene dicho `h2`.

📌 **Observación**:
- El selector `:contains(text)` es poderoso, pero también sensible a manipulaciones si no se controla adecuadamente.

🛡️ **Nota importante**:
- Aunque aquí estamos usando selectores legítimos, el mecanismo de `$()` sigue permitiendo interpretar HTML si no se maneja correctamente la entrada.

---

# 5. El problema de confiar en `location.hash`

Ahora considero el caso en que la página usa:

```javascript
$(location.hash)
```

¿Y si el atacante manipula el `hash` para poner:

```
#<img src=x onerror=alert(1)>
```

¿Qué pasaría?

- Cuando `$()` recibe `location.hash`, ve que comienza con `<`.
- Interpreta el contenido como HTML.
- **Crea un nodo DOM** malicioso.
- Se ejecuta el `onerror`, disparando **JavaScript arbitrario**.

🔥 **Punto crítico de seguridad**:
- `location.hash` **es controlado completamente por el usuario**.
- Si no se valida antes de pasarlo a `$()`, se abre la puerta a un **DOM-Based XSS**.

---

# 6. Simulando la explotación paso a paso

### 6.1 Verificando el valor de `location.hash`

```javascript
location.hash
```

- Devuelve:

```
#<img src=x onerror=alert(1)>
```

### 6.2 Pasándolo directamente a jQuery

```javascript
$(location.hash)
```

- jQuery interpreta y **crea**:

```html
<img src="x" onerror="alert(1)">
```

### 6.3 Accediendo al nodo DOM real

```javascript
$(location.hash)[0]
```

- Devuelve el **elemento `<img>` real**.

📌 **Observación**:
- No estamos seleccionando un elemento existente.
- Estamos **fabricando** un nuevo elemento DOM malicioso.

---

# 7. Por qué ocurre este comportamiento

La razón técnica es que jQuery, en versiones antiguas:

- **Verifica el primer carácter** de la cadena que recibe en `$()`.
- Si empieza con `<`, asume que debe parsear HTML y crear nodos.
- No diferencia si la entrada viene de un `hash` controlado, un formulario, o una fuente insegura.

🛡️ **Nota importante**:
- La librería confía en la estructura de la cadena.
- No valida el origen de los datos antes de parsear.

---

# 8. Conclusión técnica

Todo este análisis muestra que:

- jQuery antiguamente **confundía input controlado** por el usuario con contenido HTML legítimo.
- Esto permite crear **elementos DOM maliciosos** usando simplemente el `location.hash`.
- Si estos elementos tienen manejadores de eventos como `onerror`, `onload`, etc., permiten la **ejecución de JavaScript arbitrario**.
- El resultado final es una **vulnerabilidad DOM-Based XSS**.

🚀 **Mejoras en versiones recientes**:
- jQuery >= 3.0 introdujo protecciones para evitar este tipo de parsing inseguro.

⚡ **Advertencia**:
- Muchas aplicaciones viejas siguen usando jQuery 1.x o 2.x.
- Este tipo de vulnerabilidad sigue estando presente en aplicaciones desactualizadas.

---

# 🔥 Reflexión final

Este ejercicio demuestra la importancia de:

- No confiar en entradas controladas por el usuario (como `location.hash`).
- Validar y/o sanitizar todo dato antes de pasarlo a funciones que manipulan el DOM.
- Mantener actualizadas las librerías de frontend.
- Entender internamente cómo funcionan las herramientas que usamos (como jQuery).

---

# FIN











