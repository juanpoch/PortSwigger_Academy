## 🔒 Vulnerabilidad de Path Traversal

---

# 🔐 ¿Qué es Path Traversal?

**Path Traversal**, también conocido como **Directory Traversal**, es una vulnerabilidad de seguridad que ocurre cuando una aplicación web permite que un usuario controle la ubicación o el nombre de un archivo que se va a acceder desde el sistema de archivos del servidor, sin validar correctamente la entrada.

Esto puede permitir a un atacante:

- **Leer archivos arbitrarios** en el servidor.
- **Acceder a información sensible**, como claves privadas, configuraciones o credenciales.
- **Modificar archivos** (si también hay vulnerabilidades de escritura).
- En casos graves, **ejecutar código** o **tomar control total** del servidor.


> 🔒 Esta vulnerabilidad afecta principalmente a funciones que leen archivos del sistema mediante rutas proporcionadas por el usuario, como `?file=...`, `?page=...`, `?template=...`, etc.


---

# 🛡️ Ejemplo de funcionamiento vulnerable

Supongamos que una aplicación permite cargar imágenes mediante una URL como esta:

```html
<img src="/loadImage?filename=218.png">
```

Internamente, el backend podría tener este comportamiento:

```python
image_folder = "/var/www/images/"
requested_file = request.GET['filename']
file_path = image_folder + requested_file
```

Si se recibe `filename=218.png`, se leerá:

```bash
/var/www/images/218.png
```

Pero si un atacante envía:

```bash
filename=../../../etc/passwd
```

La ruta generada será:

```bash
/var/www/images/../../../etc/passwd
```

Y el servidor terminará leyendo:

```bash
/etc/passwd
```

> ⚠️ El uso de `../` en una ruta significa "subir un directorio". Es perfectamente válido para los sistemas de archivos.

---

# 📁 Archivos típicamente buscados por un atacante

### 🌎 Linux / Unix:

| Archivo | Propósito |
|--------|-----------|
| `/etc/passwd` | Contiene usuarios del sistema. No contiene contraseñas, pero es clave para fingerprinting. |
| `/etc/shadow` | Contiene hashes de contraseñas (protegido, pero si se accede, muy crítico). |
| `/root/.ssh/id_rsa` | Clave privada SSH del usuario root. |
| `/etc/hosts` | Mapeo interno de dominios. |
| Archivos `.env` | Claves API, tokens, configuraciones secretas. |


### 📉 Windows:

| Archivo | Propósito |
|--------|-----------|
| `C:\Windows\win.ini` | Archivo histórico, usado para prueba de lectura. |
| `C:\boot.ini` | Antiguo archivo de configuración de arranque. |
| `C:\Users\[usuario]\AppData\Roaming\...` | Tokens de aplicaciones, config locales. |
| `C:\xampp\phpMyAdmin\config.inc.php` | Si está expuesto, contiene credenciales. |

> 📅 Nota: en Windows también funciona `..\` como secuencia de subida.


[Lab: File path traversal, simple case](1_File_path_traversal_simple_case.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)  

[Dónde buscar Path Traversal](Dónde_buscar_path_traversal.md)


---

# 🔨 Técnicas para evadir validaciones

Algunas aplicaciones intentan bloquear path traversal, pero de forma deficiente. Un atacante puede intentar evadir las protecciones usando:

### 1. **Codificación URL**

```bash
%2e%2e%2f%2e%2e%2fetc%2fpasswd ➞ ../..../etc/passwd
```

### 2. **Uso de Unicode / doble codificación**

```bash
..%c0%afetc/passwd ➞ puede evadir ciertos filtros mal implementados.
```

### 3. **Uso de rutas redundantes**

```bash
....//....//etc/passwd ➞ Algunos normalizadores no manejan bien los dobles slash.
```

### 4. **Inyección en variables internas**

Si se concatena incorrectamente con variables como `base_path + user_input`, puede que un input malicioso sobreescriba rutas deseadas.


---

# 🚫 Prevención de Path Traversal

### ✅ Validación estricta de entrada:
- No permitir que el usuario especifique rutas completas.
- Usar **whitelists** de nombres de archivo permitidos.
- Rechazar cualquier input que contenga secuencias como `../`, `..\`, `%2e`, `%2f`.

### ✅ Uso de funciones seguras de resolución:
- Validar que la ruta final resultante esté dentro del directorio permitido:

```python
import os

BASE_PATH = "/var/www/images"

filename = request.GET['filename']
target = os.path.abspath(os.path.join(BASE_PATH, filename))

if not target.startswith(BASE_PATH):
    raise Exception("Invalid path")
```

### ✅ Restricciones de permisos del sistema operativo:
- Asegurar que el proceso del servidor web no tenga acceso innecesario a archivos sensibles.
- Usar usuarios de baja privilegio para ejecutar servicios web.


---

# 🚀 Impacto real

Si se explota correctamente, path traversal puede llevar a:

- **Divulgación de información crítica**.
- **Obtención de credenciales y claves API**.
- **Modificación de archivos de configuración** (si también hay LFI/RFI).
- **Acceso remoto o persistente** si se logra alterar scripts del servidor.


---

# 🎓 Conclusión

Path Traversal es una vulnerabilidad clásica pero vigente. Aunque muchos marcos modernos mitigan automáticamente este tipo de ataques, **aún es muy común encontrarla** en aplicaciones personalizadas, mal configuradas o legadas.

Es fundamental entender cómo funciona el sistema de archivos, la codificación de URLs y las funciones que manejan rutas en los lenguajes backend.

> ⚠️ Como pentester, siempre deberías probar parámetros como `file=`, `template=`, `view=`, `page=`... podrían esconder una vulnerabilidad de traversal.

---



