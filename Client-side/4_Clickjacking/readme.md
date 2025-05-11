## Clickjacking (UI redressing)

En esta guía aprenderás en profundidad qué es el clickjacking, cómo se construyen este tipo de ataques, qué variantes existen, y cómo protegerse contra ellos. También veremos ejemplos reales, el uso de herramientas como **Clickbandit**, y los mecanismos de defensa conocidos como **frame busting**.

---

## 🔐 ¿Qué es el clickjacking?

**Clickjacking** es un ataque basado en la manipulación de la interfaz de usuario (**UI redressing**) que engaña al usuario para que haga clic en contenido de otro sitio sin saberlo. Este contenido está embebido en un `iframe` invisible o transparente superpuesto a una página de apariencia inofensiva.

### Ejemplo típico:

* Un usuario accede a un sitio trampa con la promesa de ganar un premio.
* Al hacer clic en un botón visible (decoy), en realidad está haciendo clic sobre un botón invisible de un sitio vulnerable embebido en un `iframe`.
* Este botón puede, por ejemplo, **realizar un pago**, **cambiar la contraseña** o **transferir privilegios**.

Este tipo de ataque se diferencia del **CSRF** porque requiere una acción directa del usuario (clic), mientras que CSRF envía una solicitud forjada automáticamente.

---

## ⚖️ Clickjacking vs CSRF

| Característica           | Clickjacking          | CSRF                  |
| ------------------------ | --------------------- | --------------------- |
| Requiere interacción     | Sí (clic del usuario) | No (envío automático) |
| Uso de iframes           | Sí (obligatorio)      | Opcional (no necesario) |
| Dependencia visual       | Sí (engaño visual)    | No                    |
| Afectado por CSRF tokens | No                    | Sí                    |

---

## 📈 Construcción de un ataque básico de clickjacking

Un ataque clickjacking básico se puede construir utilizando HTML y CSS:

```html
<head>
  <style>
    #target_website {
      position: relative;
      width: 128px;
      height: 128px;
      opacity: 0.00001;
      z-index: 2;
    }
    #decoy_website {
      position: absolute;
      width: 300px;
      height: 400px;
      z-index: 1;
    }
  </style>
</head>
<body>
  <div id="decoy_website">
    <button>Haz clic para reclamar tu premio</button>
  </div>
  <iframe id="target_website" src="https://vulnerable-website.com"></iframe>
</body>
```

### 🔍 Explicación:

* El `iframe` carga el sitio vulnerable.
* Se posiciona justo sobre el botón falso, de manera invisible (`opacity: 0.00001`).
* Cuando el usuario hace clic, en realidad está interactuando con el contenido del iframe (sitio objetivo).

#### 🚫 Consideraciones modernas:

* Chrome desde la versión 76 incluye protecciones contra `iframes` con transparencia excesiva.
* Firefox aún **no** aplica ese tipo de detección.
* Algunos atacantes ajustan la `opacity` a valores muy bajos sin llegar a 0 para evadir esa detección.

---

[Lab: Basic clickjacking with CSRF token protection](1_Basic_clickjacking_with_CSRF_token_protection.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---
## 🛠️ Herramienta: Clickbandit

[Clickbandit](https://portswigger.net/burp/documentation/desktop/tools/clickbandit) es una herramienta incluida en **Burp Suite** que automatiza la generación de exploits de clickjacking.

### ✅ Ventajas:

* No requiere escribir HTML o CSS manualmente.
* Captura automáticamente la acción deseada sobre un `iframe` y genera un exploit listo.
* Muy útil para pruebas en aplicaciones reales durante un pentest.

---

## 💳 Clickjacking con formularios prellenados

Algunos sitios permiten prellenar formularios usando parámetros en la URL (método GET):

```url
https://vulnerable-website.com/form?amount=1000&recipient=admin
```

Esto se puede combinar con un ataque de clickjacking para presentar un formulario listo para enviar, sobre el cual el usuario haga clic sin saberlo.

### 🏛️ Ejemplo práctico:

* Se embebe el formulario prellenado en un iframe.
* El botón de "Enviar" queda perfectamente alineado con un botón falso visible.
* El usuario cree que está participando en un juego, pero en realidad está enviando una transferencia.

---

## 🚫 Prevención: Frame busting y otras técnicas

Para prevenir clickjacking, se deben **restringir los sitios que pueden embeber la página en un iframe**. Existen dos enfoques: del lado cliente y del lado servidor.

### 🔰 Encabezados HTTP recomendados (server-side):

```http
X-Frame-Options: DENY
```

O bien:

```http
X-Frame-Options: SAMEORIGIN
```

O, más flexible:

```http
Content-Security-Policy: frame-ancestors 'none';
```

### 🔧 Scripts de frame busting (client-side):

```javascript
if (top !== self) {
  top.location = self.location;
}
```

Este script verifica si la página está embebida en un `iframe`, y si es así, **redirecciona** el marco superior a la página actual, rompiendo el ataque.

---

## 🪨 Evasiones a frame busting

Algunos atacantes logran **evadir scripts de frame busting** mediante el uso de `sandbox` en el `iframe`:

```html
<iframe src="https://victim-website.com" sandbox="allow-forms"></iframe>
```

* El `sandbox` evita que el iframe tenga acceso al `top` window.
* Como resultado, **el script de frame busting no puede ejecutarse correctamente**.

Por eso, **los headers como ****************`X-Frame-Options`**************** o ****************`CSP: frame-ancestors`**************** son mucho más fiables** que los scripts client-side.

---

## 🔗 Recursos de interés

* [PortSwigger - Clickjacking](https://portswigger.net/web-security/clickjacking)
* [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
* [Burp Suite - Clickbandit](https://portswigger.net/burp/documentation/desktop/tools/clickbandit)

---
