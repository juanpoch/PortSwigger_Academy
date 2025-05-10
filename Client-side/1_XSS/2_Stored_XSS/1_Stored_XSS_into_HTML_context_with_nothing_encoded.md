# Lab: Stored XSS into HTML context with nothing encoded  

This lab contains a stored cross-site scripting vulnerability in the comment functionality.  

To solve this lab, submit a comment that calls the alert function when the blog post is viewed.  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---  

Accedemos al laboratorio y nos encontramos con un blog público, el cual tiene muchos comentarios de distintos usuarios:
![image](https://github.com/user-attachments/assets/897b6f67-6c9b-43ff-9f3c-90a4fe7f5849)

Accedemos a un comentario de otro usuario utilizando el botón `View post`:
![image](https://github.com/user-attachments/assets/6c1b6c3a-8442-4cec-b84d-bb85a4b5261f)

A su vez notamos que nosotros también podemos comentar:
![image](https://github.com/user-attachments/assets/5e783760-1038-40ca-9afd-88325e384182)



Realizamos un comentario de prueba:
![image](https://github.com/user-attachments/assets/9e471e7f-2ba1-4213-adf5-fac2f670fe55)





Vemos que nuestra inyección en el campo comentario se almacena entre etiquetas `<p>`:
![image](https://github.com/user-attachments/assets/7d49f56a-a55e-4a69-95e9-656ac7fe34bc)

![image](https://github.com/user-attachments/assets/7df45320-dd18-4f24-bf62-1899fd1ba4df)


Probamos con un payload malicioso, comenzamos inyectando etiquetas `<h1>`:  

![image](https://github.com/user-attachments/assets/8053948d-56d1-4360-bf45-bfcc295c35f0)

Notamos que las etiquetas logran inyectarse y el navegador las interpreta:  

![image](https://github.com/user-attachments/assets/472fe3ce-1a31-43b4-91d3-d9454cbfb4ae)

Por lo que ahora sí inyectamos el típico payload `<script>alert(1)</script>`:  
![image](https://github.com/user-attachments/assets/318f7bea-7cb7-43fc-8b90-4168ec90bd19)
Notamos que las etiquetas se inyectaron correctamente:
![image](https://github.com/user-attachments/assets/a9a61589-5649-4df0-8266-001cb6d3d952)


Si recargamos la página notamos que se ejecuta el popup y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/1bc9da43-7714-4f8a-b250-83ce02a9d88a)


---


---

## ✅ Conclusiones

- El laboratorio presenta una vulnerabilidad de tipo **stored XSS**, donde el contenido enviado por el usuario se almacena y se refleja directamente en el HTML sin ningún tipo de codificación o validación.
- El navegador interpreta el contenido inyectado como parte del DOM, permitiendo la ejecución automática de scripts maliciosos al visualizar la publicación.
- No existen controles preventivos por parte del backend para filtrar o sanear los comentarios.

---

## 🛡️ Recomendaciones

- Implementar **escapado adecuado en la salida** (output encoding) para todo dato proveniente de entradas del usuario.
- Aplicar **filtros y validación del lado servidor** para impedir etiquetas y atributos peligrosos como `<script>`, `onerror`, etc.
- Utilizar librerías de sanitización como **DOMPurify** en entornos JavaScript.
- Definir una **Content Security Policy (CSP)** restrictiva como capa adicional de defensa.

---

## 🎓 Lecciones aprendidas

- Las vulnerabilidades de tipo **stored XSS** son especialmente peligrosas porque afectan a múltiples usuarios sin necesidad de interacción directa con el atacante.
- El hecho de que el contenido se muestre sin codificación y dentro de un contexto HTML permite la ejecución inmediata de scripts.
- Probar primero con etiquetas inofensivas (`<b>`, `<h1>`) ayuda a entender si el navegador interpreta el contenido como HTML.
- El payload `<script>alert(1)</script>` sigue siendo una técnica válida y eficaz para confirmar la ejecución de XSS.





