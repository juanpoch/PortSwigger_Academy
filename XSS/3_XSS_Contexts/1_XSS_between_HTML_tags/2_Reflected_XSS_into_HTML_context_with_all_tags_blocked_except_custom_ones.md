Lab: This lab blocks all HTML tags except custom ones.

To solve the lab, perform a cross-site scripting attack that injects a custom tag and automatically alerts `document.cookie`.   

---

## 🎯 Objetivo del Lab

El objetivo es ejecutar `alert('XSS')` utilizando un vector de XSS reflejado, a pesar de que todas las etiquetas HTML estándar están bloqueadas. Solo se permiten etiquetas personalizadas.

---

## 🧠 Análisis del Escenario

### 🔒 Restricciones del WAF
- Bloquea etiquetas HTML estándar como `<script>`, `<img>`, `<iframe>`, etc.
- Permite etiquetas personalizadas como `<custom-tag>`.

### 🤔 ¿Qué son las etiquetas personalizadas?
- Son etiquetas no reconocidas por el estándar HTML.
- Los navegadores modernos **ignoran su funcionalidad**, pero **procesan sus atributos** como `onmouseover`, `onclick`, etc.

---

## 🚀 Procedimiento Paso a Paso

### 1. Identificar el punto vulnerable
- El parámetro `search` es vulnerable a XSS reflejado.
- El contenido del parámetro se inserta directamente en el HTML sin ser escapado adecuadamente.
![image](https://github.com/user-attachments/assets/50837f57-5fe2-4730-bc2e-6e265821aa74)



### 2. Crear un payload con etiqueta personalizada
Usamos un evento que no requiere interacción peligrosa. Por ejemplo, `onmouseover`:

```html
<custom-tag onmouseover="alert('XSS')">Pasa el cursor aqui</custom-tag>
```

Esto genera una alerta al pasar el cursor sobre el texto:
![image](https://github.com/user-attachments/assets/5d875582-ef36-45b3-9304-3d9350f337d7)


### 3. Codificar el payload para la URL

Codificamos el HTML para pasarlo por el parámetro `search`:

```
%3Ccustom-tag%20onmouseover%3D%22alert('XSS')%22%3EPasa%20el%20cursor%20aqu%C3%AD%3C%2Fcustom-tag%3E
```

### 4. Armar la URL final

Ejemplo de URL (reemplazar el dominio con el del lab):

```
https://<LAB-ID>.web-security-academy.net/?search=%3Ccustom-tag%20onmouseover%3D%22alert('XSS')%22%3EPasa%20el%20cursor%20aqu%C3%AD%3C%2Fcustom-tag%3E
```

---

## ✅ Conclusión

Aunque el WAF bloquea etiquetas conocidas, es posible ejecutar XSS explotando el hecho de que los navegadores aún procesan atributos en etiquetas desconocidas. Esto permite ejecutar JavaScript de forma efectiva.

---

- Podemos aprovechar **eventos como `onfocus`** que se disparan cuando un elemento recibe el foco.

---

## 🚀 Procedimiento Paso a Paso

### 1. Construir el Payload
Utilizamos una etiqueta personalizada `<xss>` con los siguientes atributos:
- `id="x"` → Para poder referenciarla con un ancla.
- `onfocus="alert(document.cookie)"` → El código JavaScript a ejecutar.
- `tabindex="1"` → Permite que el elemento sea enfocado automáticamente.

```html
<xss id="x" onfocus="alert(document.cookie)" tabindex="1"></xss>
```
