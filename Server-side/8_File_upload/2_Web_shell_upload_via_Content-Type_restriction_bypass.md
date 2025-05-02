# Lab: Web shell upload via Content-Type restriction bypass

This lab contains a vulnerable image upload function. It attempts to prevent users from uploading unexpected file types, but relies on checking user-controllable input to verify this.

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y nos encontramos con una aplicación de blog:
![image](https://github.com/user-attachments/assets/faf57038-5687-40c1-8632-5f9a2d63059e)

Nos autenticamos con nuestras credenciales `wiener:peter` y accedemos al dashboard del usuario:
![image](https://github.com/user-attachments/assets/1aa16cfa-7fea-4cca-b070-ed55b9321cbd)

Vemos que hay una funcionalidad para subir imágenes, en este caso como sabemos que el laboratorio tiene validaciones de tipo `Content-Type`, subimos un archivo malicioso que contiene una webshell:
![image](https://github.com/user-attachments/assets/bf61dad2-78fd-41a7-8b8c-ba4729e529c3)

El servidor nos responde que el archivo cargado tiene un content type ` application/x-php` y que sólo permite `image/jpeg` o `image/png`.

Subimos una imágen válida de prueba llamada `test.png`para analizar el proceso y vemos que se carga satisfactoriamente:
![image](https://github.com/user-attachments/assets/93fa2fe4-8349-4e42-a776-6aa1451d45e3)

Inspeccionamos el directorio de carga:
![image](https://github.com/user-attachments/assets/d2b14c2b-2f31-40f5-a463-e98929be873c)


Sabemos que la petición `POST /my-account/avatar` es la siguiente:
![image](https://github.com/user-attachments/assets/b0a121f1-2a4e-4f16-b7eb-8bd6fb0b512e)

Cargamos la web shell en php siguiente:
```php
<?php echo shell_exec($_GET['cmd']); ?>
```
Procuramos dejar el encabezado `Content-Type: image/png` tal como está, ya que éste es un encabezado permitido:
![image](https://github.com/user-attachments/assets/6cf374e1-8761-4ca1-8394-551afe7d59f8)

El servidor realiza la validación únicamente sobre el encabezado Content-Type, el cual es fácilmente manipulable por el cliente. No verifica la extensión ni inspecciona el contenido real del archivo.

Accedemos al archivo `oneliner.php`:
![image](https://github.com/user-attachments/assets/67b703ba-bc22-487e-b162-d056a7cb1f2f)


Cargamos el secreto `ofXSPhdX9rYIoQoxKqO8WkMhBtKzQ9lh` y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/39e8d0b2-533b-42dd-a3d4-6995654dce7c)

---


## ✅ Conclusión

Este laboratorio demuestra cómo una validación defectuosa basada únicamente en el encabezado `Content-Type` puede ser fácilmente eludida para cargar archivos maliciosos. Aunque el servidor intenta prevenir la ejecución de archivos peligrosos (como `.php`), confía ciegamente en los encabezados enviados por el cliente, lo cual permite al atacante disfrazar una shell web como si fuera una imagen.

A través de este bypass, pudimos subir un archivo `.php` con una webshell, accediendo a `/files/avatars/oneliner.php` y utilizando un parámetro GET para ejecutar comandos arbitrarios. En este caso, logramos leer el contenido del archivo `/home/carlos/secret` y resolver el laboratorio.

---

## 🛡️ Recomendaciones

- **No confiar en el encabezado `Content-Type` enviado por el cliente.** Este puede ser fácilmente manipulado usando herramientas como Burp Suite.
- **Validar el tipo MIME real del archivo** inspeccionando su contenido (por ejemplo, usando `file` o `finfo` en el backend).
- **Restringir extensiones a una lista blanca controlada desde el servidor.**
- **Evitar alojar archivos cargados en directorios ejecutables**, especialmente si se permiten extensiones peligrosas.
- **Aplicar permisos mínimos** en el sistema de archivos para evitar ejecución o lectura innecesaria.
- **Registrar y alertar** ante cargas sospechosas o múltiples intentos fallidos.

---

## 📚 Lecciones aprendidas

- Las validaciones superficiales pueden dar una falsa sensación de seguridad.
- Los encabezados HTTP como `Content-Type` no son confiables si provienen del lado cliente.
- Las webshells simples pueden tener un impacto crítico si se ejecutan en el servidor.
- Incluso aplicaciones que parecen tener controles pueden ser vulnerables si no se implementan de forma robusta.
- Es fundamental inspeccionar el flujo completo de carga de archivos y no asumir seguridad por “restricción visible” en el frontend.





