Lab: Information disclosure on debug page

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

🚨 Implicancias de seguridad
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





