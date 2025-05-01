# Lab: Source code disclosure via backup files

This lab leaks its source code via backup files in a hidden directory. To solve the lab, identify and submit the database password, which is hard-coded in the leaked source code.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---


Accedemos al laboratorio y tenemos una aplicación de shopping:
![image](https://github.com/user-attachments/assets/cfcf5cb2-b6e2-44c8-a595-5b8c6b2dcc80)

Debido a que el laboratorio nos dice que hay archivos de backup en un directorio oculto, procederemos a inspeccionar el `robots.txt`

---


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

---

Accedemos al `robots.txt` de la página y vemos que indica que los motores no deben indexar el directorio `/backup`:
![image](https://github.com/user-attachments/assets/84970403-a0a1-43b4-b269-775f361ad12a)

Este es un clásico error de seguridad por falsa confidencialidad.

Accedemos al directorio `/backup`:
![image](https://github.com/user-attachments/assets/61ae8a2f-40c7-47df-96e5-bb2013486231)

Encontramos una exposición directa de código fuente en el directorio `/backup`, lo cual confirma una vulnerabilidad de `Information Disclosure` por archivo de respaldo expuesto públicamente.

Accedemos al link:
![image](https://github.com/user-attachments/assets/66f62f2c-b59b-4164-9e3f-e7e2d0634e63)


Este archivo de respaldo `ProductTemplate.java.bak` confirma la divulgación crítica de información sensible, revelando las siguientes credenciales harcodeadas:
  ```java
  "postgres",
"postgres",
"ruwamxojr1seja7nt361kcac3dlfpt44"
```

Procedemos a brindar la contraseña `ruwamxojr1seja7nt361kcac3dlfpt44` y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/37f6ecfd-170b-4ae0-b651-96f442bf5005)

![image](https://github.com/user-attachments/assets/d6d7628b-0126-4ed4-ab2b-469ee658384f)


---

---

## ✅ Conclusión

Este laboratorio evidenció una vulnerabilidad de **divulgación de código fuente** mediante archivos de respaldo accesibles públicamente en un directorio oculto (`/backup`). El archivo `ProductTemplate.java.bak` contenía credenciales hardcodeadas, incluyendo el **usuario**, **contraseña**, y **parámetros de conexión a base de datos**, lo cual permitió resolver el desafío al identificar el valor de `ruwamxojr1seja7nt361kcac3dlfpt44`.

Este tipo de vulnerabilidad ilustra cómo errores simples de despliegue o configuración pueden poner en riesgo severo a toda la aplicación.

## 🛡️ Recomendaciones

- Eliminar archivos de respaldo y temporales del entorno de producción.
- Restringir el acceso a directorios sensibles mediante controles adecuados de acceso (no depender solo de `robots.txt`).
- Nunca incluir credenciales hardcodeadas en el código fuente.
- Implementar análisis estático de seguridad en los pipelines CI/CD para detectar este tipo de errores antes del despliegue.

## 📚 Lecciones aprendidas

- El archivo `robots.txt` puede ser utilizado como vector inicial de enumeración si se listan rutas sensibles.
- Directorios como `/backup`, `/dev`, `/old`, y `/config` deben ser monitoreados y protegidos.
- Los archivos `.bak`, `.old`, y similares pueden contener información crítica.
- Este tipo de fallo combina errores de **seguridad por oscuridad**, **falta de limpieza de entorno**, y **mala gestión de secretos**.
