# XSS in HTML Tag Attributes

## 🧠 Introducción

Cuando se explota una vulnerabilidad de **Cross-Site Scripting**, uno de los contextos más comunes —y al mismo tiempo más complejos— es el de las **atribuciones HTML** (HTML tag attributes). Estas situaciones ocurren cuando el valor que controlamos mediante un parámetro o entrada de usuario se inserta directamente dentro del valor de un atributo en una etiqueta HTML, como `href`, `src`, `value`, `title`, `alt`, etc.

A diferencia de los contextos HTML puros o JavaScript inline, aquí muchas veces debemos aplicar técnicas más sofisticadas para:

* Romper el atributo y salir del contexto actual.
* Inyectar un nuevo atributo con un manejador de eventos (`onfocus`, `onerror`, etc.).
* O bien aprovechar atributos ya interpretables como `href="javascript:..."`.

Esta guía cubre diferentes variantes de este tipo de XSS, con explicaciones técnicas, ejemplos prácticos y casos reales utilizados en laboratorios de PortSwigger.

---

## 💥 Caso 1: Romper un atributo y cerrar la etiqueta

### Contexto

Cuando la entrada del usuario es reflejada dentro del valor de un atributo como en:

```html
<input type="text" value="INYECCIÓN_AQUÍ">
```

Podemos intentar cerrar la comilla del atributo y luego cerrar la etiqueta o inyectar otra nueva. Ejemplo:

```html
" ><script>alert(document.domain)</script>
```

### Resultado:

Esto cierra el valor (`"`), termina la etiqueta (`>`), y comienza un nuevo `<script>` que se ejecuta en el DOM.

🔐 **Limitación frecuente:** muchos sitios filtran o codifican `<` y `>`, lo que impide el cierre de etiquetas o uso de `<script>`.

---

## ⚡ Caso 2: Inyección de nuevos atributos con eventos (`onfocus`, `onerror`, etc.)

Si no se puede insertar un `<script>`, se puede intentar romper el atributo e inyectar otro con un manejador de eventos. Ejemplo clásico:

```html
" autofocus onfocus=alert(document.domain) x="
```


### ¿Qué hace este payload?

* Termina el atributo actual (`"`).
* Inyecta `autofocus` para que el elemento obtenga el foco automáticamente.
* Define un evento `onfocus` que se dispara cuando el elemento recibe foco.
* Agrega `x="` para restaurar la sintaxis y evitar romper el HTML siguiente.

### Variantes útiles:

```html
" onmouseover=alert(1) style="position:absolute;top:0;left:0;width:100%;height:100%"
```

```html
" onmouseenter=print() x="
```

🔍 **Nota:** estos atributos funcionan solo en etiquetas que aceptan eventos, como `<input>`, `<textarea>`, `<a>`, etc.

---

[Lab: XSS in HTML tag attributes](2_XSS_in_HTML_tag_attributesd)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---


## 🔗 Caso 3: Atributos que permiten ejecución directa (`href`, `src`, etc.)

Hay algunos atributos como `href` en `<a>`, `src` en `<iframe>` o `action` en formularios, que permiten definir directamente una URI o protocolo.

### Ejemplo:

```html
<a href="javascript:alert(document.domain)">Click</a>
```

El protocolo `javascript:` es interpretado por el navegador como código ejecutable cuando el usuario hace clic.

### Consideraciones:

* Requiere interacción (clic).
* Bloqueado por algunos navegadores o políticas CSP modernas.

🔒 **Recomendación:** probar también con `data:` y `vbscript:` (en navegadores antiguos).

---

[Lab: Stored XSS into anchor href attribute with double quotes HTML-encoded](2_Stored_XSS_into_anchor_href_attribute_with_double_quotes_HTML-encoded.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

## 🧪 Caso 4: Contextos no interactivos con `accesskey` y campos ocultos

A veces el payload se refleja en atributos de etiquetas pasivas, como `<link>`, `<meta>`, `<input type="hidden">`, etc. En estos casos no hay eventos automáticos, pero pueden combinarse técnicas como `accesskey`.

### ¿Qué es `accesskey`?

Permite definir atajos de teclado para enfocar un elemento. Combinado con eventos como `onfocus`, se puede lograr ejecución sin interacción directa.

### Ejemplo:

```html
<link rel="canonical" href="x" accesskey="x" onfocus=alert(1)>
```

### Ataque:

1. El atacante usa `accesskey` con una tecla (`x`).
2. El usuario presiona `Alt + Shift + x` (en Chrome/Linux).
3. Se enfoca el elemento y se dispara `onfocus` → XSS.

🔍 **PortSwigger Research** documentó esta técnica como una forma avanzada de explotación XSS en campos ocultos o etiquetas estáticas.

---

## 🔬 Otros atributos que pueden ser utilizados

| Atributo     | Tipo de contexto      | Observaciones                               |
| ------------ | --------------------- | ------------------------------------------- |
| `href`       | Scriptable            | Permite `javascript:`                       |
| `src`        | Scriptable            | Se puede usar `onerror` si falla el recurso |
| `action`     | Navegación/formulario | Puede combinarse con `javascript:`          |
| `value`      | HTML Attribute        | Necesita salir del atributo                 |
| `title`      | HTML Attribute        | Inyectar eventos si la etiqueta lo permite  |
| `style`      | CSS context           | Posible `expression()` en IE antiguos       |
| `background` | Atributo obsoleto     | Ejecutable en navegadores antiguos          |

---

## 🛡️ Mitigaciones recomendadas

* ✂️ Escapar correctamente las comillas (`"`) dentro de atributos.
* ⛔ Bloquear `javascript:` y protocolos peligrosos en atributos como `href` o `src`.
* ✅ Validar y sanear todos los inputs antes de reflejarlos.
* 🔐 Implementar políticas CSP restrictivas.
* 🧼 Evitar usar `.innerHTML`, `.outerHTML` o `.html()` de jQuery si se puede usar `.textContent` o `.setAttribute()`.

---

---
