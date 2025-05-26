# Lab: Information disclosure on debug page

This lab contains a debug page that discloses sensitive information about the application. To solve the lab, obtain and submit the `SECRET_KEY` environment variable.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y tenemos la típica aplicación de shopping de Portswigger:
![image](https://github.com/user-attachments/assets/b04b34d5-a34f-424b-839e-20501420cc51)

Inspeccionamos la funcionalidad de `View details`:
![image](https://github.com/user-attachments/assets/47ac8307-c0c6-42a6-bbeb-738474e93df5)

Analizamos el endpoint `/` y vemos que hay un indicador claro de una posible vulnerabilidad de divulgación de información en esta respuesta HTML:
![image](https://github.com/user-attachments/assets/7d52c561-875c-4141-b2f4-f321b33c7a27)

Tenemos el siguiente comentario: 
```html
<!-- <a href=/cgi-bin/phpinfo.php>Debug</a> -->
```
Este comentario HTML indica que existe o existió un enlace al archivo `/cgi-bin/phpinfo.php`, el cual normalmente ejecuta el script `phpinfo()` de PHP.

### 🚨 Implicancias de seguridad
El archivo `phpinfo.php` es utilizado comúnmente para propósitos de debugging y muestra una gran cantidad de información sensible, incluyendo:

- Versión exacta de PHP.

- Módulos y extensiones cargadas.

- Variables del entorno (`$_SERVER`, `$_ENV`).

- Ruta completa de archivos del sistema (path disclosure).

- Detalles de configuración del servidor (por ejemplo, `display_errors`, `open_basedir`).

- Parámetros de conexión (a veces visibles si no se sanitizan adecuadamente).

Si este archivo está accesible públicamente, un atacante podría utilizarlo para:

- Mapear la superficie de ataque del servidor.

- Encontrar vectores para explotación (por ejemplo, vulnerabilidades conocidas en módulos PHP).

- Comprobar si hay configuraciones inseguras habilitadas.

- Identificar rutas locales que pueden usarse en ataques `LFI/RFI` o `File Upload`.


Accedemos al endpoint `/cgi-bin/phpinfo.php`:
![image](https://github.com/user-attachments/assets/b0d1325e-36cd-4e79-ba2f-5297ad92ded5)

![image](https://github.com/user-attachments/assets/289861c2-5f4d-4c7c-b696-6f9413a3f76e)



Esta es una exposición directa y crítica de información sensible en un entorno de producción. El endpoint `/cgi-bin/phpinfo.php` que muestra la salida de `phpinfo()` está abierto al público, lo cual es una vulnerabilidad de divulgación de información grave.

Esta captura (y lo que puede seguir al hacer scroll) revela:

- Versión completa de PHP y sistema operativo:
`PHP Version 7.4.3-4ubuntu2.29` sobre `Linux 8c94bf721940 4.14.355-275.603.amzn2.x86_64`

- Rutas internas del servidor:
Como `/etc/php/7.4/cgi/conf.d/20-xsl.ini`, `/etc/php/7.4/cgi/php.ini`, etc.

- Información de configuración detallada:
Incluyendo extensiones, sockets, módulos activados, soporte para protocolos (https, ftp, phar, tlsv1.0, etc).

- Configuración del motor Zend y OPcache, que podría ayudar a explotar vulnerabilidades específicas si alguna de las extensiones estuviera desactualizada o mal configurada.

Procedemos a buscar `SECRET_KEY` y encontramos el valor `cbf1s7t5i9upoetja42ylb02cvctyta2` asociado a la misma:
![image](https://github.com/user-attachments/assets/86248113-48de-413f-a8b5-3d7979d451aa)

Por lo que podemos resolver el laboratorio haciendo click en `Submit solution` e ingresando el valor `cbf1s7t5i9upoetja42ylb02cvctyta2 `:
![image](https://github.com/user-attachments/assets/087bf8c8-a857-4b7e-9091-f348be4b6458)

---

## ✅ Conclusión

Se identificó una vulnerabilidad de divulgación de información mediante la exposición pública de una página de debug (`/cgi-bin/phpinfo.php`) que ejecuta la función `phpinfo()` de PHP.

Este archivo reveló información sensible del entorno de ejecución, incluyendo la variable de entorno `SECRET_KEY`, cumpliendo así el objetivo del laboratorio.

## 🛡️ Recomendaciones

- Nunca desplegar archivos de depuración (`phpinfo()`, `debug.php`, etc.) en entornos de producción.
- Implementar controles de acceso para endpoints internos o reservados para desarrolladores.
- Auditar el código antes de cada despliegue para eliminar comentarios o archivos no esenciales.

## 📚 Lecciones aprendidas

- Los comentarios HTML pueden revelar rutas críticas que faciliten el descubrimiento de funcionalidades internas.
- La función `phpinfo()` puede exponer datos sensibles como rutas internas, variables de entorno y configuraciones del servidor.
- La inspección manual y el uso de herramientas como Burp Suite ayudan a detectar detalles que los escáneres automáticos podrían pasar por alto.








