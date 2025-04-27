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









