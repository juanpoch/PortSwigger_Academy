# Lab: Remote code execution via web shell upload

This lab contains a vulnerable image upload function. It doesn't perform any validation on the files users upload before storing them on the server's filesystem.

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y tenemos una aplicación de blog:
![image](https://github.com/user-attachments/assets/a5f37019-79ba-47b9-8860-5e1844a9c7a6)

Accedemos al panel de autenticación y nos logueamos con nuestras credenciales `wiener:peter`. Observamos el endpoint `/my-account?id=wiener`:
![image](https://github.com/user-attachments/assets/dd34d67f-d5d9-44c5-b16d-a1b7266a3a3d)

Notamos que tenemos una funcionalidad de carga de archivos, por lo que subimos una imagen de prueba para analizarla. Cargamos la imágen y haceos click en `Upload`:
![image](https://github.com/user-attachments/assets/90924fc6-07f2-4171-9b09-41c2e65fc4ad)

Volvemos a nuestra cuenta y se ve nuestra imagen cargada:
![image](https://github.com/user-attachments/assets/d783779d-77c1-4659-a74c-7d2acd0d6a41)

Analizamos la petición de carga con Burp Suite:
![image](https://github.com/user-attachments/assets/320ae37c-b5e5-4549-9fcf-0885d5a9e8f9)

Esta captura muestra una operación de carga de archivos típica, en la que el usuario sube un archivo llamado `test.png` mediante un formulario `multipart/form-data` al endpoint `/my-account/avatar`.

`Nota`: En Burp Suite, en la pestaña `http history`, recordar hacer click en `Filter settings`, tildar `Images` y luego click en `Apply`:
![image](https://github.com/user-attachments/assets/6050600a-3e62-4ae4-ae85-9e71f4eaf9f3)

Con esta configuración, vemos las imágenes cargadas y vemos el directorio de carga `/files/avatars/`:
![image](https://github.com/user-attachments/assets/ed057386-db66-49ef-b559-54ee578ed851)

El directorio de carga también podemos visualizarlo en el DOM inspeccionando el elemento:
![image](https://github.com/user-attachments/assets/aabc2011-304d-4300-b83c-f134744da87d)


Volviendo al endpoint `/my-account/avatar`, intentamos subir un archivo malicioso que contiene el siguiente oneliner en PHP:
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```
![image](https://github.com/user-attachments/assets/fe451865-d1f4-4719-b11e-99c632740f94)

`Nota`: También podríamos haber probado la siguiente webshell:
```php
<?php system($_GET['cmd']); ?>
```

Esta captura es una explotación directa y crítica de una vulnerabilidad de carga de archivos sin restricciones (unrestricted file upload) que permite ejecutar código arbitrario en el servidor.

🚨 Impacto:
- Ejecución remota de código: Si luego accededemos al endpoint `files/avatars/test.php`, el servidor ejecutará ese archivo como código PHP. El resultado será la lectura del archivo `/home/carlos/secret`, cuyo contenido se devolverá en la respuesta HTTP.

- Escalada total de privilegios: Si el archivo PHP se ejecuta correctamente, el atacante gana control total sobre el servidor (web shell). En este caso puntual, permite acceder a información confidencial del usuario carlos.

Accedemos al endpoint `files/avatars/test.php` y leemos el archivo `/home/carlos/secret`:
![image](https://github.com/user-attachments/assets/7b53328b-11d1-4b03-986d-f56512b9c8f7)

Alternativamente podríamos intentar subir la web shell:
![image](https://github.com/user-attachments/assets/50e6e04c-a261-4ac5-a368-66e61c4b09ed)

Accedemos al endpoint y `files/avatars/webshell.php` y obtenemos la shell:
![image](https://github.com/user-attachments/assets/c6a2c5df-8413-450b-a63e-0b0851bc2c2a)


Cargamos el secreto `ayk86WeXNI5eIMewigMgSCGXt9NYSu5F` y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/7c9e5c4c-2d48-4fd6-8b9d-083044d7a463)

---

## ✅ Conclusión

Este laboratorio demuestra una de las vulnerabilidades más críticas asociadas a cargas de archivos: la ejecución remota de código (RCE) mediante una web shell. La aplicación permite subir archivos sin ningún tipo de validación de tipo, extensión o contenido, lo que posibilita que un atacante cargue archivos `.php` con código malicioso. Como el directorio de destino permite la ejecución de estos scripts, es posible ejecutar comandos arbitrarios o leer archivos sensibles como `/home/carlos/secret`.

Este tipo de falla puede comprometer completamente el servidor, permitiendo desde robo de datos hasta pivoting dentro de la red interna.

---

## 🛡️ Recomendaciones

- **Validar la extensión del archivo del lado del servidor**: No confiar en el tipo MIME enviado por el cliente. Implementar listas blancas de extensiones válidas (por ejemplo: `.jpg`, `.png`, `.gif`).

- **Verificar el contenido del archivo (content sniffing)**: Comprobar que los archivos realmente correspondan al tipo declarado. Herramientas como `file` en sistemas Unix pueden ayudar a identificar tipos verdaderos.

- **Renombrar archivos al subirlos**: Para evitar la ejecución de código malicioso con nombres controlados por el atacante.

- **Almacenar archivos en directorios no ejecutables**: El directorio de subida no debe tener permisos para ejecutar scripts del lado servidor.

- **Bloquear extensiones peligrosas a nivel de servidor web (Apache/Nginx)**: Configurar reglas que impidan la ejecución de archivos `.php`, `.jsp`, `.asp`, etc. en directorios públicos.

- **Limitar los permisos del usuario del servidor**: Evitar que tenga acceso innecesario a rutas críticas como `/home/carlos/`.

---

## 📚 Lecciones aprendidas

- Una simple funcionalidad de subida de imagen puede ser usada como vector de ataque crítico si no se aplica una validación rigurosa.

- El análisis de las rutas y el comportamiento del servidor ante diferentes extensiones es clave para detectar directorios ejecutables.

- Burp Suite y el análisis del DOM permiten identificar rutas de subida, extensiones aceptadas y puntos de explotación.

- Las web shells son herramientas extremadamente poderosas para post-explotación, y deben considerarse como pruebas de concepto de gran impacto en cualquier pentest profesional.

