# HTTP Host Header Attacks&#x20;

## 🔐 Qué es la cabecera HTTP Host

La cabecera `Host` es obligatoria en todas las peticiones HTTP/1.1. Indica el dominio al que el cliente desea acceder. Por ejemplo:

```
GET /admin HTTP/1.1
Host: example.com
```

Es usada por el servidor para direccionar correctamente la petición al backend apropiado (especialmente en entornos con virtual hosts o balanceadores de carga).

---

## 🧵 Contextos comunes donde se usa Host

### ✉️ Virtual Hosting

Múltiples sitios web en un mismo servidor/IP. El `Host` permite distinguir a cuál dominio pertenece la petición.

### ↔️ Reverse Proxies / CDNs

El `Host` ayuda a enrutar correctamente la petición hacia el backend correspondiente.

---

## ⚠️ Qué es un ataque de Host header

Son ataques que explotan aplicaciones que **confían de forma insegura en el valor de la cabecera Host**. El atacante puede modificarla para:

* Envenenar cachés compartidas (Web Cache Poisoning)
* Generar enlaces maliciosos (Password reset poisoning)
* Bypassear autenticaciones
* Forzar redirecciones
* Realizar SSRF basados en enrutamiento

Ejemplo de uso riesgoso:

```html
<a href="https://HOST/support">Soporte</a>
```

Donde `HOST` se toma del header sin validación previa.

---

## 🔎 Casos de uso comunes en ataques

### ⚠️ 1. Password Reset Poisoning

Algunas apps generan enlaces de reseteo de contraseña usando el `Host`:

```
https://malicious.com/reset?token=abc123
```

El atacante intercepta el flujo y reemplaza `Host: example.com` por `Host: malicious.com`, enviando el mail con el link malicioso.

### ⚠️ 2. Web Cache Poisoning

Si la caché toma en cuenta el `Host` como clave, puede envenenarse con contenido alterado.

### ⚠️ 3. SSRF mediante enrutamiento

Si el `Host` se usa para determinar el destino del backend, se puede forzar al servidor a hacer requests internas.

---

## 🧪 Por qué ocurren estas vulnerabilidades

* Suposición errónea de que `Host` no es controlable por el usuario.
* Dependencia en `Host` para generar URLs absolutas o decisiones lógicas.
* Configuraciones inseguras de proxies y balanceadores (ej: soporte por defecto de `X-Forwarded-Host`).

---

## 🥷🏻 Detección de vulnerabilidades

### Paso 1: Cambiar manualmente el Host

Modificá la cabecera `Host` con Burp Suite a un dominio controlado:

```
Host: attacker.com
```

Observá si la respuesta refleja ese valor en redirecciones, links generados, emails enviados, etc.

### Paso 2: Probar con cabeceras alternas

Algunos sistemas soportan:

* `X-Forwarded-Host`
* `X-Host`
* `X-Forwarded-Server`

### Paso 3: Revisar comportamientos inusuales

* URLs absolutas alteradas
* Redirecciones sospechosas
* Variaciones en contenido cacheado
* Generación de correos o links manipulables

---

## 🚀 Prevención

### 1. Evitá usar URLs absolutas

Usá URLs relativas siempre que sea posible.

### 2. No confiar en Host / Validar Host

* Validalo contra una lista blanca (whitelist).
* Frameworks como Django tienen `ALLOWED_HOSTS`.

### 3. No soportar cabeceras de override

* Desactivá `X-Forwarded-Host` si no es necesario.

### 4. Configuración segura de infraestructura

* Evitá que dominios internos compartan IP con dominios públicos.
* Configurá correctamente los reverse proxies para no redirigir por `Host` sin validación.

---

