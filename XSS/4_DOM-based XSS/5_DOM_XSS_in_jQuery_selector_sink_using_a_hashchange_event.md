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

Si buscamos una cadena dentro de una etiqueta `h2` en la sección `blog-list`, por ejemplo, la cadena `The Peopleless Circus`:
![image](https://github.com/user-attachments/assets/0e4d24a3-98de-4fcc-a663-3d205a2c0990)


Si la añadimos como hashtag, vemos que el script actúa y se realiza un scroll down hacia ese elemento:
![image](https://github.com/user-attachments/assets/27bd6be4-c4af-44f5-84e1-d760a54ce6e5)



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



# 1. Accedemos al primer y único elemento de la colección

- Si el selector encuentra un elemento `<h2>` dentro de `section.blog-list` cuyo contenido de texto contiene `"The Peopleless Circus"`, jQuery me devuelve una **colección** que contiene ese elemento.

Ahora, si intento acceder directamente al primer elemento de esa colección utilizando `[0]` o `.get(0)`:

![image](https://github.com/user-attachments/assets/b155d125-3492-42cf-ba2d-190fef59d746)

- Obtengo el **nodo DOM real** (sin envoltorio de jQuery).

---

# 2. Qué pasa cuando intento acceder a un elemento no existente

Ahora pruebo qué ocurre si el selector **no encuentra** ningún elemento:
![image](https://github.com/user-attachments/assets/dd2f7bcb-02e8-4e3e-8d9a-a969b384877e)
La consola muestra undefined, ya que la operación de asignar una variable no tiene valor de retorno visible.

Si observamos la variable `post`:
![image](https://github.com/user-attachments/assets/e164939d-6ea7-4308-ac63-6657d5836d00)
- `post` contiene una colección jQuery vacía.

- No hay ningún elemento en su interior.

- Su propiedad `.length` es igual a 0.


Comprobamos la existencia de `post`:  

![image](https://github.com/user-attachments/assets/2fd60e54-0509-4938-80aa-b3231ceeadd4)

- Estamos verificando si post existe o no.

- En JavaScript, una colección jQuery siempre es un objeto, incluso si está vacía.

- Por eso, if (post) siempre evalúa a true, aunque no haya elementos en su interior.


Y si intento acceder al primer elemento:

![image](https://github.com/user-attachments/assets/9c38e303-6423-40b5-b413-6020cf224708)


- Obtengo **undefined**.

🛡️ **Nota importante**:
- Si el selector no encuentra ningún elemento que cumpla el criterio de búsqueda (por ejemplo, `<h2>` que contenga el texto esperado), **no hay errores**, simplemente jQuery devuelve una colección vacía.
- No se crean nuevos elementos. **No hay manipulación del DOM**.

⚡ **Advertencia**:
- Es normal que `[0]` sea `undefined` si la colección jQuery está vacía, ya que no hay ningún elemento que devolver.

---

# 3. Analizando entrada controlada: HTML 

Ahora me pregunto: qué sucede si, insertamos etiquetas html al selector `contains`:

Por ejemplo:

![image](https://github.com/user-attachments/assets/f0768491-711e-45dd-bacd-f66b34f905f2)


¿Qué hace jQuery?

![image](https://github.com/user-attachments/assets/24eb61a4-6f1f-4974-9108-c8ffd08337c2)

Por qué está indicando que hay un march, si no existe ninguna etiqueta `h1` en el código. Como el elemento tiene un lenght de 1, podemos exponer el objeto con:  

![image](https://github.com/user-attachments/assets/cf67cd1b-9356-4d44-9378-3986c93960b9)  

Este elemento contiene nuestro texto arbitrario:  

![image](https://github.com/user-attachments/assets/c2e1a780-6a4b-4c1a-b1b5-5ad587511103)  


# 📚 ¿Qué significa esto realmente?

- jQuery interpreta mal el contenido malformado y **crea un nodo DOM real** (`<h1>` en este caso).
- Sin embargo, **este nodo no está adjuntado al documento**: existe en memoria, pero no forma parte del DOM visible.
- No se inserta automáticamente en `document.body` ni en ningún otro contenedor.

---

# 🛡️ Nota de seguridad:

- Aunque se crea un elemento DOM, mientras no se inserte en la página, **no hay impacto visual ni ejecución de eventos**.
- Sin embargo, manejar entradas malformadas puede llevar a errores de lógica o a inyecciones si después se inserta ese contenido dinámicamente.

---

# ✅ Resumen

- `:contains()` trata su contenido como texto, pero cuando el contenido es malformado puede provocar **creación de nodos en memoria**.
- Estos nodos **no se insertan** automáticamente en el DOM de la página.





- En versiones antiguas (pre 3.0), **detecta que empieza con `<`** y lo **interpreta como HTML**, no como un selector.
- **Crea un elemento** real en memoria: una etiqueta.

📌 **Observación**:
- jQuery **parsea la entrada** y **genera nodos reales** si ve un fragmento HTML.

🛡️ **Nota importante**:
- Este comportamiento es completamente automático si se usan versiones antiguas de jQuery.
- En versiones recientes (>=3.0), este comportamiento fue cambiado para evitar problemas de seguridad.
  

---  



Ahora sobrescribimos `post` para que ya no sea una colección jQuery, sino el nodo DOM puro:  

![image](https://github.com/user-attachments/assets/95bf3047-b21b-4269-ab1f-149c89d75779)  


Si prestamos atención al código fuente, podemos ver un elemento arbitrario que tenga un id, por ejemplo:  


![image](https://github.com/user-attachments/assets/3d7c9963-7c7f-47ac-8418-01cd4a587d1e)

Ahora guardamos la referencia a ese nodo en la variable `mynode`:  

![image](https://github.com/user-attachments/assets/6f55ed6d-253f-4682-b1b4-f9ba1e688a4a)

Finalmente, insertamos el `<h1>` en el DOM real con:  

![image](https://github.com/user-attachments/assets/4731e071-e565-485a-949c-8cfd1d24e0d3)

---

Ahora creamos dinámicamente un nuevo elemento HTML mediante JavaScript:  

![image](https://github.com/user-attachments/assets/3124ea4d-f5b3-4791-8970-90a5e286851a)

Luego de crear el elemento `<img>`, asignamos un valor a su atributo `src`:  

![image](https://github.com/user-attachments/assets/a6e1d22b-cbab-474a-a0db-a711e8a229e8)

- Asignamos el valor 0 al atributo src del elemento myimg.

- El navegador interpreta automáticamente este valor como una URL relativa:
`https://[dominio_del_lab]/0`

- Se dispara una solicitud HTTP GET hacia esa URL.

- El servidor responde con un error 404 Not Found.

- Esto indica que el recurso `/0` no existe en el servidor.


---

En el siguiente ejemplo intentamos ir más allá con la inyección de etiquetas:

![image](https://github.com/user-attachments/assets/e1f3f2df-6011-4ca2-8d00-06ba9f0bf41b)

- Insertamos un elemento `<img>` dentro del selector.

- Definimos `src="0"` para forzar que el navegador intente cargar una imagen que no existe.

- Agregamos `onerror="alert(1)"` para que se ejecute un alert(1) si la carga falla.

---

Ejecutamos la inyección en la url:
![image](https://github.com/user-attachments/assets/9b867145-bdcb-427d-8830-e3ee19af6db1)












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











