# Lab: File path traversal, simple case

This lab contains a path traversal vulnerability in the display of product images.

To solve the lab, retrieve the contents of the `/etc/passwd` file.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)  


---

Iniciamos el lab y observamos una aplicación que nos permite comprar objetos, los mismos tienen información asociada, incluidos precios e imágenes:
![image](https://github.com/user-attachments/assets/fbc7056b-2f23-4a7b-b479-8a4b6ea088cd)

Como sabemos que este laboratorio se trata sobre `path traversal`, procedemos a inspeccionar el elemento `<img>` de una foto:
![image](https://github.com/user-attachments/assets/e31acdc3-8f00-4656-9d4c-f96b4b1350ca)

Esto indica que las imágenes no se cargan directamente desde una ruta estática (`/images/22.jpg`), sino a través de una ruta dinámica controlada por parámetro `GET /image?filename=22.jpg`

Lo más probable es que el backend esté haciendo algo similar a lo siguiente:
```python
file_path = "/var/www/images/" + filename
```

Esto es exactamente el tipo de comportamiento vulnerable a `Path Traversal`, si no hay validación o sanitización adecuada.

Si el servidor no valida el valor del parámetro filename, podrías intentar enviar algo como:
```bash
/image?filename=../../../etc/passwd
```

Y si `/var/www/images/../../../etc/passwd` se resuelve correctamente y se lee desde el disco, se habría explotado una vulnerabilidad de `Path Traversal`.

Si abrimos la imágen en una pestaña nueva vemos que se realiza una petición al recurso con el valor del parámetro `filename=22.jpg`:
![image](https://github.com/user-attachments/assets/83cdf174-58fb-4496-a45f-3c8ce9322a4e)


Podemos intentar visualizar las distintas imágenes simplemente modificando el parámetro:
![image](https://github.com/user-attachments/assets/cfe9ef63-6a65-4421-8cac-27c72020d0b6)

Podemos intentar buscar archivos en rutas del sistema, por ejemplo si buscamos en `../etc/passwd` nos dice que no encontró el archivo que se busca:
![image](https://github.com/user-attachments/assets/6489e341-c3f7-4ba2-bc96-6ed5c34396a7)

Esto podría suceder porque una ruta posible donde inicia la búsqueda podría ser `"/var/www/images/"`, por lo que dirigiendonos un directorio hacia atrás, no estaríamos encontrando esos archivos.

Entonces intentamos ir hacia atrás varios directorios buscando el archivo `../../../etc/passwd`:
![image](https://github.com/user-attachments/assets/233437da-ec72-4d40-b037-797be4308f9c)

El servidor está respondiendo que el archivo existe pero no lo está pudiendo leer, probablemente porque no es una imágen, sino que es texto.

Esto se debe a que el servidor responde con la cabecera `content-type: image/jpg`, por lo que no está dispuesto a mostrar texto que no pueda ser renderizado como imagen:
![image](https://github.com/user-attachments/assets/6dd3cb94-c2ec-4a33-ada3-1977a4dbf991)








