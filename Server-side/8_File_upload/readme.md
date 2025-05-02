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
