# DOM XSS in jQuery selector sink using a hashchange event

This lab contains a DOM-based cross-site scripting vulnerability on the home page. It uses jQuery's `$()` selector function to auto-scroll to a given post, whose title is passed via the `location.hash` property.

To solve the lab, deliver an exploit to the victim that calls the `print()` function in their browser.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)

---

## 🧪 Introducción al laboratorio

Este laboratorio presenta una vulnerabilidad de tipo **DOM-based Cross-Site Scripting** que se manifiesta en el uso inseguro del fragmento de URL (`location.hash`) en combinación con jQuery.

El sitio vulnerable implementa una funcionalidad de **scroll automático** que utiliza el valor del hash (`#`) para localizar dinámicamente una entrada de blog y desplazar la vista hasta ese elemento. Esto se realiza mediante un selector jQuery `:contains(...)`, que recibe el contenido directamente desde el `hash` de la URL, sin ninguna sanitización o validación previa.

Este comportamiento puede ser manipulado por un atacante para inyectar contenido HTML malicioso, como una etiqueta `<img>` con un atributo `onerror`, y lograr así la ejecución de JavaScript arbitrario en el navegador de la víctima.

Nuestro objetivo será:

- Comprender cómo jQuery maneja la entrada controlada en los selectores.
- Manipular el `hash` para inyectar un nodo `<img>` con código malicioso.
- Automatizar el ataque utilizando un `<iframe>` que desencadene el evento `hashchange` y dispare el exploit sin necesidad de interacción del usuario.

La explotación exitosa del laboratorio requiere lograr que el navegador de la víctima ejecute la función `print()` como prueba de concepto del XSS.

---

Iniciamos el laboratorio y nos encontramos con el siguiente website:
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

Primero quiero entender qué pasa si uso jQuery de forma tradicional, seleccionando elementos existentes en el DOM.

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

![image](https://github.com/user-attachments/assets/41959142-5b40-4a63-8628-6e058692f247)


Por qué está indicando que hay un mach, si no existe ninguna etiqueta `h1` en el código. Como el elemento tiene un lenght de 1, podemos exponer el objeto con:  

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
![image](https://github.com/user-attachments/assets/1167d675-08f6-4a01-9c84-6f7b6112421e)

# Automatización con `iframe`

Como escribimos en la teoría, un atacante puede usar `iframe` para explotar la vulnerabilidad sin interacción directa del usuario:

```html
<iframe src="https://vulnerable-website.com#" onload="this.src += '<img src=1 onerror=alert(1)>'"></iframe>
```

Qué sucede:

- Se carga el iframe apuntando a la página vulnerable con un `hash` vacío.
- Cuando el `iframe` termina de cargar (`onload`), automáticamente modifica su propio `src` para agregar un vector XSS al `hash`.
- Esta modificación activa el evento `hashchange` en la página vulnerable.
- Se ejecuta el código malicioso (por ejemplo, `alert(1)`) de manera automática.

Diferencia clave: En este caso, no se necesita que el usuario interactúe manualmente (por ejemplo, no hace falta que haga clic ni escriba nada). El navegador procesa automáticamente la carga y modificación del iframe, ejecutando el ataque en segundo plano.


Utilizamos el siguiente payload:
```html
<iframe src="https://0a75007c03f5cbc1e3b8176b00650086.web-security-academy.net/#" onload="this.src += '<img src=0 onerror=print()>'"></iframe>
```

Utilizamos el exploit server para cargar nuestro html:
![image](https://github.com/user-attachments/assets/09e817f2-9394-498a-a594-879154efcd63)



Luego click en `Deliver exploit to victim` y resolvemos el lab:
![image](https://github.com/user-attachments/assets/f4cd5610-8b2c-45bb-b885-79375fd1ba34)


---
## ✅ Conclusión estructurada paso a paso

### 1. `location.hash` como fuente de entrada controlada
Todo lo que el usuario coloque después del `#` en la URL se extrae mediante `window.location.hash`, se decodifica y se **inyecta directamente** dentro de un selector jQuery `:contains(...)` — sin ningún tipo de sanitización.

---

### 2. jQuery interpreta mal input HTML en selectores
Cuando el selector `:contains(...)` recibe contenido con etiquetas HTML malformadas, **jQuery interpreta eso como HTML real** y puede llegar a crear nodos DOM **en memoria** (aunque no visibles ni insertados automáticamente).

---

### 3. Inyección de `<img>` con `onerror` para ejecutar código
Si el nodo creado es una etiqueta `<img>`, el navegador intentará cargar la URL indicada en `src`. Si esa imagen no existe (por ejemplo, `src=0`), se dispara el evento `onerror`, lo que permite ejecutar JavaScript arbitrario como `alert(1)` o `print()`.

---

### 4. Uso de `iframe` para automatizar el ataque (sin interacción)
La vulnerabilidad se explota **sin intervención del usuario** usando un `iframe` que:

- Carga la página vulnerable con un `hash` vacío.
- Luego modifica dinámicamente su propio `src` para incluir el payload malicioso en el `hash`.
- Esto desencadena el evento `hashchange`, **activando el XSS automáticamente**.

---

🔒 Todo este flujo representa un **clásico DOM-based XSS** utilizando:
- `jQuery` como **sink**
- `location.hash` como **source**
- y un **vector HTML malformado** como entrada.


---

## ✅ Conclusiones

- Este laboratorio presenta una vulnerabilidad **DOM-based XSS**, donde el valor de `location.hash` se usa sin sanitización dentro de un selector jQuery.
- jQuery interpreta ciertas entradas como fragmentos HTML y puede crear nodos DOM en memoria si la entrada es malformada.
- Si bien estos nodos no se adjuntan automáticamente al DOM, pueden ser manipulados o insertados manualmente para provocar una ejecución de código.
- Usamos un `iframe` con `onload` para automatizar la modificación del hash y activar el exploit sin interacción del usuario.

---

## 🛡️ Recomendaciones

- Nunca usar directamente entradas del usuario en constructores de selectores como `:contains(...)` sin validación ni escape.
- Actualizar jQuery a versiones recientes (3.x o superiores), que no permiten la interpretación de fragmentos HTML dentro de selectores.
- Usar funciones seguras para manipular el DOM como `textContent`, `createElement` y evitar `.html()` o `.innerHTML` con contenido no confiable.
- Aplicar políticas de **Content Security Policy (CSP)** que bloqueen esquemas peligrosos y la ejecución de scripts inyectados.

---

## 🎓 Lecciones aprendidas

- Las vulnerabilidades **DOM XSS** pueden activarse a partir de propiedades como `location.hash`, `location.search`, `document.referrer`, etc.
- El selector `:contains()` en jQuery es susceptible si se combina con entrada controlada por el usuario.
- El uso de `iframe + onload` permite automatizar ataques de tipo DOM XSS, simulando a una víctima real sin interacción manual.
- En Chrome moderno, funciones como `alert()` están bloqueadas en iframes cross-origin, por lo que se recomienda usar `print()` como alternativa.

