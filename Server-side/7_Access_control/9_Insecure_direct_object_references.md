# Lab: Insecure direct object references

This lab stores user chat logs directly on the server's file system, and retrieves them using static URLs.

Solve the lab by finding the password for the user `carlos`, and logging into their account.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y nos encontramos con una aplicación de shopping, la cual tiene una nueva funcionalidad de `Live chat`:
![image](https://github.com/user-attachments/assets/67d91861-c104-46b1-8752-2795b9b44b34)

Accedemos a la funcionalidad de `Live chat` y vemos que tenemos un panel de chat donde podemos escribir mensajes y recibir respuestas:
![image](https://github.com/user-attachments/assets/4c7d7433-d0e8-45c6-bf4b-2e2530d29f9c)

![image](https://github.com/user-attachments/assets/c71181b6-446a-4c67-8f9f-9bad4acfb8af)

Si hacemos click en `View transcript` nos descarga un archivo con nuestra conversación:
![image](https://github.com/user-attachments/assets/e37b4ada-c794-4da3-b588-290eaf01271b)

Esta captura muestra una vulnerabilidad de IDOR basada en el acceso directo a archivos estáticos. Lo que está ocurriendo:

- La URL `/download-transcript/2.txt` hace referencia directa a un archivo `.txt` ubicado en el servidor.

- El archivo contiene una transcripción de la conversación.

- No hay ningún tipo de control de acceso que impida que el usuario autenticado lea archivos de otros usuarios simplemente incrementando o modificando el ID numérico (2.txt, 3.txt, etc.).

Enviamos la petición al `Repeater` e intentamos descargar otros archivos:
![image](https://github.com/user-attachments/assets/f42ab105-4f5e-4ee2-a8b8-140e022c4132)

Esta nueva captura confirma completamente la explotación de la vulnerabilidad IDOR sobre archivos estáticos con impacto crítico:

- Se accede al archivo `/download-transcript/1.txt` sin ningún tipo de autenticación contextual ni control de acceso.

- La transcripción contiene una contraseña en texto plano:
  ```text
  om3kkg8b83phgt6sn2ci
  ```

🔴 Impacto:
Esta vulnerabilidad IDOR permite el acceso a archivos confidenciales sin autenticación contextual. En este caso, deriva en la exposición de credenciales sensibles que permiten autenticación no autorizada y toma de control de otra cuenta.

💡 Este es un caso típico de IDOR + falta de control de acceso + información sensible mal gestionada.

Procedemos a iniciar sesión como `carlos` con las credenciales `carlos:om3kkg8b83phgt6sn2ci` y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/7301b27d-9454-4f3b-a66e-be13f053e1a7)


---

## ✅ Conclusión

En este laboratorio se identificó una vulnerabilidad de tipo **Insecure Direct Object Reference** en la funcionalidad de descarga de transcripciones de chat. La aplicación permite a cualquier usuario autenticado acceder a archivos estáticos en el servidor, cuya ruta es predecible (`/download-transcript/<id>.txt`), sin aplicar ningún tipo de validación o control de acceso contextual. Como consecuencia, fue posible acceder a conversaciones ajenas y extraer **información altamente sensible**, incluyendo una contraseña en texto plano perteneciente a otro usuario (`carlos`), lo que permitió una **escalada horizontal de privilegios**.

---

## 🔐 Recomendaciones

- Implementar controles de acceso en el servidor que verifiquen que el usuario autenticado tiene permiso para acceder al recurso solicitado, incluso si se trata de archivos estáticos.
- Evitar el uso de identificadores secuenciales o predecibles en rutas sensibles. Considerar el uso de UUIDs o tokens firmados por sesión.
- Nunca almacenar ni servir contraseñas en texto plano, ni siquiera en elementos de tipo `input type="password"` pre-cargados en el DOM.
- Utilizar almacenamiento más seguro y controlado para información confidencial, en lugar de archivos expuestos directamente en el sistema de archivos accesibles por URL.
- Implementar registros de acceso a archivos confidenciales para detectar posibles abusos o patrones de exploración maliciosa.

---

## 📚 Lecciones aprendidas

- Los archivos estáticos también deben estar sujetos a controles de acceso si contienen información sensible.
- Las vulnerabilidades de tipo IDOR pueden tener un impacto **crítico** si el recurso expuesto incluye credenciales, tokens o información privada.
- El hecho de que algo no esté enlazado directamente en la interfaz no significa que no pueda ser accedido si la ruta es predecible.
- Nunca se deben reflejar contraseñas o datos sensibles en HTML, incluso si están "enmascarados", ya que son visibles en el código fuente y en las herramientas del navegador.
