## 🧠 Guía completa: Web Cache Deception

La **Web Cache Deception** (WCD) es una vulnerabilidad que permite a un atacante engañar a un sistema de caché para que almacene contenido dinámico y sensible, generalmente privado de un usuario. Esto ocurre cuando existen **diferencias de interpretación** entre el servidor de origen y el sistema de caché sobre cómo manejar ciertas solicitudes. Estas diferencias pueden ser aprovechadas para que contenido personalizado, como información de cuentas, historial de pedidos o tokens, quede almacenado y accesible públicamente mediante una URL predecible.

---

## ❗ Diferencia con Web Cache Poisoning

| Técnica             | Objetivo principal                                              |
| ------------------- | --------------------------------------------------------------- |
| Web Cache Deception | Obtener datos privados almacenados en caché                     |
| Web Cache Poisoning | Contaminar el caché con contenido malicioso para otros usuarios |

Mientras la WCD tiene como objetivo **leer datos sensibles**, el poisoning busca **inyectar respuestas** que luego verán otros usuarios. Ambos explotan diferencias en la interpretación de URLs o headers por parte del sistema de caché, pero con fines distintos.

Para más información sobre cache poisoning, consultar la guía de [Web Cache Poisoning](https://portswigger.net/web-security/web-cache-poisoning).

---

## 📦 ¿Qué es un sistema de caché web?

Una caché web se sitúa entre el cliente y el servidor de origen. Su propósito es mejorar la eficiencia y velocidad del sitio al evitar que recursos estáticos o que cambian poco sean servidos repetidamente desde el servidor original. El flujo básico es:

1. El cliente solicita un recurso (por ejemplo, `/style.css`).
2. Si la caché no lo tiene (*cache miss*), se reenvía la solicitud al servidor de origen.
3. El servidor responde y la caché almacena la respuesta según las reglas configuradas.
4. Si otra solicitud solicita el mismo recurso, la caché responde directamente (*cache hit*), reduciendo el tiempo de carga.

> ⚡ Las CDNs (Content Delivery Networks) como Cloudflare, Akamai o Fastly implementan estas técnicas a escala global.

---

## 🔑 Cache Keys

La caché decide si puede responder directamente una solicitud basándose en su **clave de caché**, que es una combinación de elementos del request:

* URL completa (dominio + ruta + parámetros)
* Método HTTP (`GET`, `HEAD`, etc.)
* Headers relevantes (`Accept-Language`, `Cookie`, `User-Agent`, etc.)

Si dos requests generan la misma clave de caché, el sistema considera que pueden compartir la misma respuesta.

🔎 *Ejemplo:* Estas dos URLs generan distintas claves:

* `/profile` → clave A
* `/profile?cb=123` → clave B (distinta por el parámetro)

---

## 🧱 Reglas de caché comunes

Los sistemas de caché se configuran con reglas que determinan qué contenido es elegible para almacenamiento:

| Regla                | Ejemplo de coincidencia       |
| -------------------- | ----------------------------- |
| Extensión de archivo | `/profile.js`, `/style.css`   |
| Directorio estático  | `/static/*`, `/assets/*`      |
| Archivo específico   | `/robots.txt`, `/favicon.ico` |

Otras reglas avanzadas pueden evaluar:

* Cabeceras (`Cache-Control`, `Authorization`)
* Longitud de la respuesta
* Tipo MIME del contenido (`text/css`, `application/json`, etc.)

---

## 🧪 ¿Cómo se construye un ataque Web Cache Deception?

1. **Identificar un endpoint sensible:** Por ejemplo, `/my-account` o `/order-history`, que devuelven datos personalizados.
2. **Detectar una discrepancia de mapeo entre caché y servidor:** Esto implica que el servidor ignora segmentos adicionales como `/my-account/test.css`, pero la caché los considera parte de un recurso estático.
3. **Agregar una extensión estática falsa:** Para que la caché lo trate como archivo estático (`.css`, `.ico`, etc.).
4. **Hacer que la víctima acceda a la URL manipulada:** La respuesta, personalizada, se almacena en la caché.
5. **El atacante accede a la misma URL:** Y ve el contenido cacheado (sin autenticación).

📌 *Este ataque suele ser efectivo en sitios con sesiones basadas en cookies, y donde el backend devuelve contenido sensible a usuarios autenticados.*

---

## 🧰 Uso de Cache Busters

Durante pruebas, es clave evitar respuestas cacheadas anteriores. Para eso se usan **cache busters**:

* Agregá parámetros únicos en cada solicitud:

  ```
  /profile/test.js?cb=1673832
  ```
* Usá la extensión **Param Miner** en Burp:

  * Menú `Param Miner > Settings > Add dynamic cachebuster`
  * Esto asegura que cada request tenga una clave de caché diferente

💡 *Ideal para automatizar fuzzing sobre múltiples endpoints sin interferencias.*

---

## 🕵️ Cómo detectar si una respuesta está cacheada

Revisá estas cabeceras:

* `X-Cache: hit` → Servida desde la caché
* `X-Cache: miss` → Aún no almacenada, pero probablemente lo esté en el próximo request
* `X-Cache: dynamic` → Generada por backend, no apta para caché
* `X-Cache: refresh` → Se reemplazó una copia antigua
* `Cache-Control: public, max-age=3600` → Se puede almacenar por 1 hora

⏱️ También es útil comparar tiempos de respuesta: una diferencia significativa puede indicar que una respuesta fue cacheada.

---

## 🧪 Ejemplo de ataque por discrepancia de mapeo REST vs Caché

### URL base:

```http
GET /user/123/profile
```

Devuelve información del usuario 123.

### URL modificada:

```http
GET /user/123/profile/falso.css
```

* El servidor REST probablemente ignora `/falso.css` y sigue entregando el perfil.
* La caché lo interpreta como `/profile/falso.css` y lo guarda si está permitida la extensión `.css`.

🔓 Ahora esa URL puede ser accedida por cualquiera, incluso sin sesión.

---

## 🧪 Otra técnica: extensiones estáticas agregadas

Muchos endpoints toleran parámetros extra en la URL:

```http
/api/orders/456 → pedido #456
/api/orders/456/falso.ico → contenido idéntico
```

Si obtenemos una respuesta idéntica y la caché lo almacena, ya hay una vulnerabilidad.

✅ Probar con:

* `.css`
* `.js`
* `.ico`
* `.html`
* `.exe`
* `.png`

📌 *Importante: no todas las rutas son vulnerables, ya que la lógica del backend puede variar según el endpoint.*

---

## 🧰 Herramientas útiles

* **Burp Repeater:** para manual testing y comparar respuestas
* **Burp Param Miner:** automatiza el cache busting y parámetro discovery
* **Web Cache Deception Scanner (BApp):** escaneo automático de discrepancias
* **Logger / HTTP History:** para analizar headers de caché como `X-Cache`

Adicionalmente:

* Usar **Burp Intruder** con extensiones `.css`, `.ico`, etc., para testeo masivo
* Monitorizar **diferencias en cookies** (algunas apps cachean respuestas que no deberían si no usan cookies correctamente)

---

## 🛑 Precauciones durante el testeo

* Evitá acceder a la URL maliciosa desde el navegador mientras estés logueado como víctima: podrías activar redirecciones o borrado de sesión.
* Utilizá **Burp** o una herramienta de línea de comandos (como `curl`) para controlar la respuesta sin redirección automática.
* Si descubrís una respuesta cacheada, **verificá si es reutilizable sin autenticación**.

---

## 🧠 Resumen de pasos para explotar WCD

| Paso | Acción                                                                                |
| ---- | ------------------------------------------------------------------------------------- |
| 1️⃣  | Identificá un endpoint con datos dinámicos personalizados (ej. `/account`, `/orders`) |
| 2️⃣  | Probá agregando segmentos falsos como `/account/falso.css`                            |
| 3️⃣  | Compará si la respuesta sigue incluyendo contenido privado                            |
| 4️⃣  | Observá cabeceras (`X-Cache: hit`) para confirmar que fue almacenado                  |
| 5️⃣  | Repetí el request sin sesión: si ves la misma info, ¡hay vulnerabilidad!              |

---

[Lab: Exploiting path mapping for web cache deception](1_Exploiting_path_mapping_for_web_cache_deception.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

