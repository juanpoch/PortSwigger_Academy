# Lab: Source code disclosure via backup files

This lab leaks its source code via backup files in a hidden directory. To solve the lab, identify and submit the database password, which is hard-coded in the leaked source code.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---


Accedemos al laboratorio y tenemos una aplicación de shopping:
![image](https://github.com/user-attachments/assets/cfcf5cb2-b6e2-44c8-a595-5b8c6b2dcc80)

Debido a que el laboratorio nos dice que hay archivos de backup en un directorio oculto, tenemos los principales archivos que generalmente se buscan en un pentesting:

- robots.txt


## Análisis de `robots.txt`: Implicancias en Seguridad

### ¿Qué es el archivo `robots.txt`?
El archivo `robots.txt` es un archivo de texto ubicado en la raíz de un sitio web (por ejemplo, `https://ejemplo.com/robots.txt`) que está diseñado para comunicar instrucciones a los crawlers o bots de motores de búsqueda (como Googlebot). Su función principal es controlar el acceso de estos bots a ciertas partes del sitio web.

### Sintaxis Básica
Un archivo `robots.txt` puede contener reglas como:

```
User-agent: *
Disallow: /admin/
```

Esto indica que **todos los bots** (`User-agent: *`) tienen prohibido acceder a la ruta `/admin/`.

### Uso Legítimo
- Evitar la indexación de páginas duplicadas o irrelevantes.
- Prevenir la sobrecarga del servidor evitando que los bots rastreen rutas pesadas.
- Mantener ocultas ciertas secciones del sitio de los buscadores (aunque no seguras).

### Implicancias en Seguridad
Aunque `robots.txt` **no tiene fines de seguridad**, es común encontrar errores de configuración que terminan exponiendo información sensible. Algunos ejemplos:

#### 1. Revelación de Rutas Sensibles
La inclusión de rutas en `Disallow` puede alertar a un atacante sobre recursos ocultos como:
- `/backup/`
- `/admin/`
- `/config/`
- `/old_site/`

Estas rutas, aunque no indexadas por buscadores, siguen siendo accesibles manualmente o mediante herramientas de pentesting.

#### 2. Exposición de Interfaces de Desarrollo
Es común ver entradas como:
```
Disallow: /dev/
Disallow: /staging/
```
Estas rutas podrían apuntar a entornos de prueba inseguros, donde no se aplican las mismas medidas de seguridad que en producción.

#### 3. Ayuda para Enumeración
Un atacante puede usar `robots.txt` como punto de partida para un ataque de **fuerza bruta de directorios** o **descubrimiento de contenido**.

### Robots.txt en Pentesting
En una evaluación de seguridad, siempre se recomienda revisar `robots.txt` como uno de los primeros pasos de reconocimiento:

- Usar Burp Suite, curl o simplemente el navegador para acceder: `https://objetivo.com/robots.txt`
- Analizar si contiene rutas que pueden conducir a:
  - Interfaces administrativas.
  - APIs no documentadas.
  - Archivos de respaldo.
  - Repositorios internos o paneles.

Ejemplo en Burp Suite:
```
GET /robots.txt HTTP/1.1
Host: objetivo.com
```

### Buenas Prácticas de Seguridad
- No confiar en `robots.txt` como mecanismo de protección.
- No incluir rutas sensibles en `robots.txt`; mejor proteger con autenticación y control de accesos.
- Usar `robots.txt` sólo para su propósito: gestión de indexación.
- Revisar periódicamente el contenido de `robots.txt` para asegurarse de que no filtre información innecesaria.

### Conclusión
El archivo `robots.txt`, aunque diseñado para la gestión de bots, puede volverse una fuente de información sensible para un atacante. En pentesting, representa un recurso clave en la etapa de **reconocimiento pasivo** y puede revelar rutas valiosas para la enumeración y exploración del objetivo. Su gestión adecuada es vital para evitar fugas de información inadvertidas.


