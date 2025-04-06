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

Enviá una carga útil simple que ejecute JavaScript si no es filtrada.

🎯 **Payload recomendada**:
```html
<script>alert(document.domain)</script>
```
### 🧪 Usá Burp Repeater para probar una carga útil candidata

1. **Enviá la solicitud** original con el valor alfanumérico aleatorio (por ejemplo, `abc123xy`) al Burp Repeater.
2. **Sustituí ese valor** por una **carga útil XSS candidata**, como:
   ```html
   <script>alert(document.domain)</script>
   ```
3. **Dejá el valor original** junto con el payload, si querés mantener una referencia. Por ejemplo:
   ```text
   abc123xy<script>alert(document.domain)</script>
   ```
4. **Usá el valor alfanumérico como término de búsqueda (grep)** en la vista de respuesta de **Burp Repeater**.

- Esto permite **resaltar rápidamente** todos los lugares donde se refleja tu entrada.

5. **Revisá el contexto** donde aparece reflejado en la respuesta HTML para determinar si puede ejecutarse como JavaScript.

🧠 **Tip**: Al entender el contexto, podés elegir o ajustar la carga útil adecuada para lograr la ejecución del script.

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



   
