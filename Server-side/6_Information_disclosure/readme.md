# Information disclosure


Las **vulnerabilidades de divulgación de información**, también conocidas como *information disclosure* o *information leakage*, se producen cuando una aplicación web **revela involuntariamente datos sensibles** a los usuarios. Esta información puede ser:

- Datos de otros usuarios (nombres, direcciones de email, información financiera)
- Datos comerciales o confidenciales de la empresa
- Detalles técnicos del sitio web o la infraestructura subyacente (versiones, rutas, IPs, etc.)

Si bien algunos datos pueden parecer triviales, incluso la más pequeña fuga puede ser utilizada por un atacante como una **pieza clave para realizar ataques más complejos**, como inyecciones, escaladas de privilegios o bypass de autenticaciones.

## Ejemplos típicos

Algunos ejemplos comunes de divulgación de información:

- **robots.txt o directory listing** expone la estructura de directorios y archivos ocultos.
- Acceso público a archivos de código fuente, *logs* o *backups* (".bak", ".old").
- **Mensajes de error** que revelan nombres de tablas, rutas del sistema o trazas internas.
- Comentarios HTML visibles en el *frontend* con información sensible.
- Claves API, credenciales o tokens embebidos en JavaScript o código cliente.
- Diferencias sutiles en los tiempos o mensajes que permiten inferir usuarios válidos o archivos existentes.

## ¿Cómo surgen estas vulnerabilidades?

Las causas más comunes incluyen:

### 1. Contenido interno no eliminado
- Comentarios de desarrollo expuestos en HTML.
- Rutas de debug visibles ("/debug", "test.php", etc).

### 2. Mala configuración de la aplicación o servidor
- Features de debugging habilitadas en producción.
- Configuración por defecto de servidores o CMS (por ejemplo, phpinfo()).

### 3. Lógica deficiente
- Mostrar mensajes de error diferenciados para cada caso ("usuario no existe" vs. "contraseña incorrecta").
- Respuestas HTTP o mensajes específicos según el estado interno del sistema.

## Impacto de la divulgación de información

El impacto depende de **qué tipo de información se revela**:

- **Créditos o tarjetas** de clientes: impacto crítico.
- **Datos técnicos** (versiones, estructuras, rutas): impacto variable, pero puede permitir ataques de mayor gravedad.

Ejemplo: Saber que el sitio usa `Apache 2.4.29` puede parecer inofensivo. Pero si esa versión es vulnerable a un exploit conocido, **el atacante tiene medio camino hecho**.

## Evaluando la severidad

No toda divulgación amerita un reporte crítico. Algunas claves para evaluarlo:

- ¿Permite escalar a otra vulnerabilidad más grave?
- ¿Se trata de información confidencial o financiera?
- ¿Es explotable de forma remota y sin autenticación?

Es importante no reportar *falsos positivos*. Datos menores sólo se deben reportar si tienen **explotabilidad clara**.

## ᵇᴿᵖ – ¿Cómo encontrar y explotar estas vulnerabilidades?

### 1. Inspeccionar los comentarios HTML
Muchos desarrolladores dejan comentarios como:
```html
<!-- TODO: desactivar debug en prod -->
<!-- API_KEY = 'abc123' -->
```
Usar Ctrl+U o herramientas como "View source" o DevTools para revisar.

### 2. Forzar errores
- En formularios de login, enviar un usuario válido y contraseña errónea.
- Observar si el mensaje cambia según la validez del usuario.

### 3. Buscar archivos olvidados
Usar *Discover Content* de Burp Suite, `ffuf`, `dirsearch` o `gobuster` para detectar:
```
.bak
.php.old
/admin/
/backup/
/config.php~
```

### 4. Revisar cabeceras y respuestas HTTP
Algunas veces, las cabeceras contienen:
```
X-Powered-By: PHP/5.6.40
Server: Apache/2.4.49 (Ubuntu)
```
O errores como:
```
Fatal error: Uncaught exception 'PDOException'...
```

## ᴿᵉᵒ – Prevención

- **Usar mensajes genéricos** para errores ("credenciales inválidas" en vez de "usuario inexistente").
- **Eliminar comentarios de desarrollo** en producción.
- **Desactivar debugging y verbose logging** en ambientes públicos.
- **Validar archivos expuestos**: evitar backups o archivos temporales accesibles.
- **Revisar configuración de terceros**: si usás frameworks o CMS, revisá qué headers o rutas se exponen por defecto.
- **Auditorías regulares de seguridad** y uso de herramientas automáticas para buscar leaks.

## ᵃᵉᵒ – Conclusión

Las vulnerabilidades de *Information Disclosure* no deben subestimarse. Aunque por sí solas muchas veces no permiten explotar el sistema directamente, pueden **ser el trampolín para ataques más complejos**. La información es poder, y en ciberseguridad, **cada bit cuenta**.

Aprender a reconocer, evaluar y explotar estas fugas es una habilidad esencial para cualquier analista, pentester o bug bounty hunter.


