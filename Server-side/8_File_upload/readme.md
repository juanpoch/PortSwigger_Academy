## Vulnerabilidades de Carga de Archivos

Las vulnerabilidades de carga de archivos permiten a un atacante subir archivos maliciosos a un servidor web. Cuando no se validan correctamente el nombre, el tipo, el contenido o el tamaño de los archivos, se pueden producir **fallos críticos de seguridad**, incluyendo ejecución remota de código, escalación de privilegios, denegación de servicio, o exfiltración de información confidencial.

---

### ✨ ¿Qué es una vulnerabilidad de carga de archivos?

Una vulnerabilidad de este tipo ocurre cuando una aplicación permite que los usuarios carguen archivos sin implementar controles rigurosos sobre:

* **El nombre del archivo** (puede sobrescribir archivos importantes)
* **La extensión del archivo** (puede permitir scripts ejecutables como .php, .jsp)
* **El tipo MIME** (puede ser manipulado fácilmente con Burp o herramientas similares)
* **El contenido del archivo** (por ejemplo, que contenga código malicioso)
* **El tamaño del archivo** (riesgo de DoS llenando el disco)

Incluso si el archivo es subido con éxito, el impacto depende de cómo se gestiona luego:

* ¿Es ejecutado?
* ¿Es accesible vía URL pública?
* ¿Hay verificaciones en el backend antes de servirlo?

---

### 🔥 Impacto potencial

El peor escenario posible ocurre cuando el servidor **acepta archivos ejecutables** como `.php` y está **configurado para ejecutarlos como código**. Esto permite subir una **web shell** y tomar el control del servidor.

Otros riesgos incluyen:

* Sobrescritura de archivos sensibles si no se valida el nombre del archivo
* Escalada de directorio (Directory Traversal) si se permite navegar fuera del directorio previsto
* DoS si se suben archivos grandes en cantidad para llenar el disco

---

### ⚠️ Causas comunes

* **Listas negras mal implementadas:** por ejemplo, bloquear ".php" pero permitir ".php3", ".phtml", etc.
* **Validación basada en el nombre del archivo** y no en el contenido
* **Verificación sólo del lado cliente** (JavaScript que impide subir .php, pero no se valida del lado servidor)
* **Configuraciones inconsistentes entre directorios** (por ejemplo, en `/uploads/` no se ejecutan scripts, pero en `/static/uploads/` sí)

---

### ⚙️ Cómo los servidores manejan archivos estáticos

Cuando se realiza una petición para un archivo estático como una imagen o un `.css`, el servidor:

1. **Lee la extensión** del archivo
2. **Asigna un tipo MIME** según una tabla predefinida
3. Decide si **lo sirve como texto plano** o **lo ejecuta** (si es .php, .jsp, etc.)

Por ejemplo:

* `image.jpg` → `Content-Type: image/jpeg` → el contenido es enviado al navegador
* `script.php` → si el servidor está configurado para ejecutar PHP, lo procesa y ejecuta

El encabezado `Content-Type` puede revelar qué tipo de archivo el servidor cree que está sirviendo.

---

### 🚫 Malas prácticas comunes

* Permitir subir archivos `.php`, `.jsp`, `.aspx` sin verificación adecuada
* Almacenar archivos en un directorio accesible vía web sin restricciones (por ejemplo, `/uploads/`)
* No restringir el contenido interno del archivo (ej: subir una imagen PNG con código PHP embebido)

---

### ⚡ Explotando cargas de archivo para desplegar una Web Shell

Una **Web Shell** es un script malicioso que permite ejecutar comandos en el servidor vía HTTP. Por ejemplo:

```php
<?php echo file_get_contents('/etc/passwd'); ?>
```

Pasos típicos para explotar:

1. Subir el archivo `.php` con el código de la web shell
2. Acceder a la URL donde fue almacenado (por ejemplo, `/uploads/shell.php`)
3. Ejecutar comandos pasando parámetros GET o POST

Ejemplo de Web Shell con comando remoto:

```php
<?php echo shell_exec($_GET['cmd']); ?>
```
```php
<?php system($_GET['cmd']); ?>
```
Esto permitiría ejecutar comandos como:

```
GET /uploads/shell.php?cmd=ls
```

---

### ✅ Buenas prácticas para prevenir cargas maliciosas

* **Lista blanca** de extensiones permitidas, validando tanto el nombre como el contenido (MIME real)
* Almacenar los archivos **fuera del directorio accesible vía web**, y servirlos solo tras validación
* Cambiar el nombre de los archivos subidos por un **hash o UUID** para evitar colisiones o predicción
* Verificar el contenido del archivo usando librerías como `file`, `exif_imagetype`, o `magic_bytes`
* Configurar el servidor para **no ejecutar código** en los directorios de carga (`uploads/`)

---

### 🔹 Resumen

Las vulnerabilidades de carga de archivos son extremadamente peligrosas y pueden tener consecuencias devastadoras. Identificarlas y explotarlas requiere entender:

* Cómo el servidor procesa las extensiones
* Dónde se almacenan los archivos
* Cómo se validan (o no) los datos subidos

Una función de carga de imagen aparentemente inocente puede convertirse en un vector para ejecutar una web shell y comprometer completamente el servidor.

A continuación se aplicarán estos conceptos en un laboratorio práctico para identificar y explotar una función de carga vulnerable:

[Lab: Remote code execution via web shell upload](1_Remote_code_execution_via_web_shell_upload.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---


## 🔍 Explotación de una validación defectuosa en la carga de archivos

Las funcionalidades de carga de archivos son objetivos comunes en un pentest, pero rara vez están completamente desprotegidas. En lugar de eso, lo más habitual es encontrar **mecanismos de validación débiles o mal implementados** que permiten **bypassear restricciones** y lograr la ejecución de código en el servidor.

---

### 🧪 Validación basada en Content-Type: ¿por qué es peligrosa?

Al subir un archivo con un formulario HTML, el navegador genera una solicitud `POST` con el encabezado:

```
Content-Type: multipart/form-data
```

Esto permite dividir el cuerpo del mensaje en distintas partes, una por cada campo del formulario. Cada parte incluye su propio encabezado `Content-Disposition` y, opcionalmente, un `Content-Type` que **el cliente** (navegador o herramienta como Burp) declara como tipo MIME del archivo.

**Ejemplo real de payload generado por el navegador:**

```
---------------------------012345678901234567890123456
Content-Disposition: form-data; name="image"; filename="example.jpg"
Content-Type: image/jpeg

[binary data de example.jpg]
```

Ahora bien, **¿qué pasa si el servidor confía ciegamente en este `Content-Type: image/jpeg` para validar que el archivo es una imagen?**

> 👉 Esto es problemático porque **el atacante puede modificar este encabezado en Burp Suite**, y hacer pasar un archivo `.php` con código malicioso como si fuera una imagen.

---

### 🛠️ Ejemplo de explotación con Burp Repeater

Supongamos que el atacante desea subir una web shell en PHP. Puede interceptar la petición en Burp y modificar:

* El nombre del archivo: `shell.php`
* El encabezado `Content-Type: image/jpeg` → lo mantiene igual para engañar al servidor
* El contenido: código PHP

```http
Content-Disposition: form-data; name="avatar"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
```

Si el servidor **sólo revisa el `Content-Type`** (sin inspeccionar el contenido real ni validar la extensión en el backend), la carga pasará como válida. Si el directorio de subida permite ejecución de scripts, el atacante podrá hacer una petición como:

```
GET /files/avatars/shell.php?cmd=id
```

Y recibirá la respuesta ejecutada en el servidor.

---

### 🧠 ¿Cómo detectar esta validación débil durante un pentest?

1. **Subir un archivo válido (por ejemplo, una imagen `.png`) y capturar la petición.**
2. **Reenviar desde el Repeater** modificando:

   * El nombre del archivo (ej: `shell.php`)
   * El `Content-Type` → mantenelo como `image/png` o `image/jpeg`
   * El contenido real → reemplazalo por código PHP
3. Observar si la respuesta es exitosa.
4. Intentar acceder al archivo cargado desde la URL correspondiente.

---

### 💨 Impacto

* Si el archivo es ejecutado como código, **permite RCE**.
* Incluso si no se ejecuta, puede permitir **phishing, XSS o almacenamiento de cargas maliciosas**.
* Una validación superficial basada en encabezados **es trivial de evadir con herramientas como Burp Suite**.

---

### 🛡️ Mitigación correcta

* **No confiar nunca en encabezados controlados por el cliente**, como `Content-Type`.
* **Validar la extensión y contenido real del archivo** (con herramientas como `file`, `exiftool` o Magic Numbers).
* **Limitar la ejecución de archivos**: almacenar archivos en directorios no accesibles o sin permisos de ejecución.
* **Renombrar archivos** para evitar el uso de nombres arbitrarios como `shell.php`.

[Lab: Web shell upload via Content-Type restriction bypass](2_Web_shell_upload_via_Content-Type_restriction_bypass.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

