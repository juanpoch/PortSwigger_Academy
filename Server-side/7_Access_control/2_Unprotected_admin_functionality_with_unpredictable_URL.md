# Lab: Unprotected admin functionality with unpredictable URL

This lab has an unprotected admin panel. It's located at an unpredictable location, but the location is disclosed somewhere in the application.

Solve the lab by accessing the admin panel, and using it to delete the user `carlos`.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el lab y nos encontramos con una aplicación de shopping:
![image](https://github.com/user-attachments/assets/f5cba30f-c8a8-496c-b1e2-d994b04b89d2)

Como sabemos que tenemos que encontrar un panel de administración, procederemos a buscarlo de todas las formas manuales posibles antes de realizar fuerza bruta.

Lo primero que vamos a hacer es buscar el `robots.txt` pero recibimos el mensaje `Not Found`:
![image](https://github.com/user-attachments/assets/b6628a18-3ddd-4bfe-8ad2-51b117f9573a)

Procedemos a analizar el código fuente en búsca de enlaces ocultos y comentarios:
![image](https://github.com/user-attachments/assets/70c70653-b000-4eb5-847c-6e5ec2118e95)

Filtramos la búsqueda por `admin` en el código fuente y encontramos el directorio `admin-k94nm6`:
![image](https://github.com/user-attachments/assets/f1d8964b-973d-466d-8489-ec95ac0e2e49)
Aunque el valor de isAdmin impide mostrar visualmente el enlace, el código sigue estando presente en el HTML que se sirve a todos los usuarios, incluyendo usuarios no administradores.

Este es un ejemplo de cómo un atacante puede descubrir rutas sensibles simplemente inspeccionando el código fuente (HTML o JavaScript):

- El usuario común no ve el enlace, pero la ruta está hardcodeada y visible.

- Esto invalida la idea de que una URL impredecible equivale a seguridad.

- Un atacante puede copiar esta ruta directamente y acceder al panel de administración si no hay verificación adicional del lado servidor.





Accedemos al panel de administración sin ningún tipo de restricciónes:
![image](https://github.com/user-attachments/assets/96d38fa4-62ec-47fc-b3ee-2377d757fa61)

Vemos que podemos eliminar usuarios, eliminamos el usuario `carlos` y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/ad422f45-3ce8-4c76-8c1e-5e8c9df71062)


---

## ✅ Conclusión

Se identificó una vulnerabilidad de control de acceso basada en **“seguridad por oscuridad”**, donde el panel administrativo estaba disponible en una URL oculta pero **no protegida adecuadamente del lado servidor**.

Aunque el frontend no mostraba el enlace si el usuario no era administrador, el código fuente contenía la ruta **hardcodeada**, permitiendo a un atacante descubrirla fácilmente mediante inspección del HTML o JavaScript. El acceso no requería autenticación adicional ni validación de privilegios.

Este caso demuestra que confiar únicamente en la **obfuscación de rutas** no es una medida de seguridad efectiva.

## 🛡️ Recomendaciones

- **Nunca confiar en la ocultación de URLs** como mecanismo de protección.
- **Implementar control de acceso robusto en el backend**, verificando que el usuario autenticado tenga privilegios suficientes antes de procesar solicitudes sensibles.
- **Evitar filtrar rutas sensibles en el código fuente** o archivos JavaScript entregados al cliente.
- Incorporar pruebas automáticas para detectar rutas expuestas sin protección adecuada.

## 📚 Lecciones aprendidas

- La visibilidad del enlace en el navegador no garantiza la protección del recurso.
- El análisis del código fuente puede revelar rutas ocultas o funcionalidades restringidas.
- La seguridad por oscuridad es un enfoque débil que debe complementarse con mecanismos de control real del lado servidor.
- Las pruebas manuales como inspeccionar HTML y JavaScript siguen siendo fundamentales para descubrir vulnerabilidades lógicas.



