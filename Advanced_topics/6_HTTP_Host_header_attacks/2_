# Identificar y explotar vulnerabilidades en el header HTTP Host

## 🔎 Introducción

Las vulnerabilidades en el header `Host` permiten a un atacante manipular el comportamiento del servidor mediante el envío de valores arbitrarios o ambiguos. Estas fallas surgen por confiar en que el valor de `Host` es seguro y reflejan problemas de validación o configuración.

---

## 🔮 Metodología para detectar vulnerabilidades

### 1. Enviar un header `Host` arbitrario

Modificar el header `Host` con un dominio falso y observar el comportamiento:

```http
GET / HTTP/1.1
Host: attacker.com
```

* Si el sitio responde normalmente, puede haber una configuración por defecto vulnerable.

### 2. Buscar validaciones defectuosas

Algunos servidores validan parcialmente el `Host`, permitiendo bypasses:

```http
Host: vulnerable.com:malicioso
Host: sub.vulnerable.com
Host: notvulnerable.com (dominio que termina igual)
```

### 3. Enviar headers ambiguos o duplicados

#### Headers duplicados:

```http
Host: vulnerable.com
Host: attacker.com
```

* Si frontend y backend interpretan diferentes valores, puede haber inconsistencias aprovechables.

#### URLs absolutas:

```http
GET https://vulnerable.com/ HTTP/1.1
Host: attacker.com
```

#### Encabezado indentado (line wrapping):

```http
    Host: attacker.com
Host: vulnerable.com
```

### 4. Usar headers alternativos de override

Probar con headers que pueden ser interpretados por componentes intermedios:

```http
Host: vulnerable.com
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-HTTP-Host-Override: attacker.com
```

Utilizar extensiones como **Param Miner** en Burp Suite para automatizar la detección.

---

## 🚀 Explotación de vulnerabilidades comunes

### 1. Password Reset Poisoning

Manipular el `Host` para que el link enviado al usuario apunte al dominio del atacante:

```http
Host: exploit-server.net
```

### 2. Web Cache Poisoning

Reflejar el header `Host` en la respuesta y lograr que un servidor de caché lo almacene:

```http
Host: attacker.com
```

### 3. Inyección clásica en el servidor

Enviar payloads clásicos como:

```http
Host: ' OR 1=1--
```

### 4. Bypass de autenticación o acceso interno

Algunas aplicaciones permiten acceso solo si `Host` es interno:

```http
Host: internal.vulnerable.com
```

---

## 🛡️ Prevención

* \*\*Evitar depender del header \*\***`Host`** para generar URLs absolutas.
* **Validar ****`Host`**** contra una lista blanca de dominios válidos.**
* **Ignorar headers como ****`X-Forwarded-Host`**** a menos que se necesiten y se validen.**
* **Separar ambientes internos de los accesibles al público.**

---

## 📖 Lecturas recomendadas

* [Password reset poisoning](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning)
* [Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning)
* [Request smuggling](https://portswigger.net/web-security/request-smuggling)

---

## 🕊️ Conclusión

El header `Host` es un vector poderoso para ataques si no se maneja correctamente. Mediante técnicas como duplicación de headers, uso de valores alternativos y manipulación del entorno, es posible explotar desde vulnerabilidades clásicas hasta errores lógicos en flujos críticos como restablecimiento de contraseñas o almacenamiento en caché.
