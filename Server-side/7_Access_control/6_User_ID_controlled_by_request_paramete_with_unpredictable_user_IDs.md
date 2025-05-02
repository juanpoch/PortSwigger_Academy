# Lab: User ID controlled by request parameter, with unpredictable user IDs

This lab has a horizontal privilege escalation vulnerability on the user account page, but identifies users with GUIDs.

To solve the lab, find the GUID for carlos, then submit his API key as the solution.

You can log in to your own account using the following credentials: `wiener:peter`

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y nos encontramos con un blog:
![image](https://github.com/user-attachments/assets/dd31b2b1-2231-47ad-9f38-99348007699b)

Nos logueamos con nuestras credenciales `wiener:peter`:
![image](https://github.com/user-attachments/assets/8c934bb3-a823-4fb6-83e5-5bde1999f594)

Observamos la petición en Burp Suite:
![image](https://github.com/user-attachments/assets/004cd884-648c-48c1-927c-a32162db934c)

Notamos que en este caso, el user id contiene un parámetro impredecible: `0c8e792e-d4fc-4089-bb6e-6ecdbf2df33d`

Procedemos a buscar parámetros id correspondientes a otros usuarios.

Vamos al `home` donde se encuentran todos los posts:
![image](https://github.com/user-attachments/assets/98ca9ce0-9786-4285-83d2-e59c842d41cd)

En esta petición filtramos por `id` sin encontrar nada relevante:
![image](https://github.com/user-attachments/assets/38446d94-43be-46f8-a81f-448e986917ed)

Ingresamos a un post haciendo click en `View post` y vemos que hay un post de carlos:
![image](https://github.com/user-attachments/assets/bf56eed7-eea4-4174-9857-31a7795ca471)

Inspeccionamos la petición en Burp Suite y filtramos por id:
![image](https://github.com/user-attachments/assets/576fa094-db5f-4670-af9a-0943e40c505d)

En el html se observa en la respuesta el siguiente link:
```html
<a href='/blogs?userId=3850e63e-623c-43e6-bada-1db432d511f6'>
```
Esto revela el userId de otro usuario, en este caso asociado a `carlos`.

Este hallazgo es un excelente ejemplo práctico de cómo una aplicación puede exponer identificadores sensibles (como UUIDs) de otros usuarios, lo cual puede facilitar un ataque de escalada horizontal de privilegios mediante una vulnerabilidad IDOR.


Si el backend no valida que el userId corresponde al usuario autenticado, un atacante podría usar ese userId directamente para intentar explotar un IDOR y acceder a información o funciones ajenas.

Procedemos a utilizar el endpoint `/my-account?id=0c8e792e-d4fc-4089-bb6e-6ecdbf2df33d` en el `Repeater`, cambiando el valor del parámetro `id` por `3850e63e-623c-43e6-bada-1db432d511f6`:
![image](https://github.com/user-attachments/assets/1ea54118-2059-4063-8801-095be701459d)

Respuesta exitosa:

- El backend no implementa una comprobación del ownership del recurso solicitado, lo que permite que cualquier usuario autenticado acceda a datos ajenos

- Se muestra información sensible de carlos, incluyendo su API Key:

```text
lsgjTqEQJPVnGHMURjRTwf7z9nXtBTGd
```

Por lo que obtuvimos las siguientes fallas de seguridad:
- Broken Access Control / IDOR:
El backend confía en el parámetro id sin verificar si corresponde al usuario autenticado, permitiendo el acceso directo a objetos ajenos.

- UUID disclosure + IDOR chain:
Aunque se usen identificadores UUID impredecibles, la aplicación los expone en el frontend, facilitando al atacante su recolección y posterior explotación mediante una vulnerabilidad IDOR. Esto demuestra que la seguridad no debe basarse únicamente en la ofuscación.

- Impacto crítico:
El atacante accede a una API Key sensible que puede utilizarse para autenticación o para acceder a funcionalidades restringidas de la aplicación de forma programática.



Procedemos a brindar la API Key de carlos `lsgjTqEQJPVnGHMURjRTwf7z9nXtBTGd` y resolver el laboratorio:
![image](https://github.com/user-attachments/assets/520924f8-f175-462e-8df5-e0a56d91d6ce)

---



---

## ✅ Conclusión

Se explotó con éxito una vulnerabilidad de **Insecure Direct Object Reference (IDOR)** mediante el uso de un identificador de usuario (UUID) expuesto en la interfaz pública de la aplicación. Esta falla permitió realizar una **escalada horizontal de privilegios**, accediendo a la cuenta de otro usuario y obteniendo su **API Key**, sin validación de ownership del recurso.

La aplicación asocia los datos sensibles al parámetro `id` de forma directa y confía en que el cliente no manipulará su valor, lo que representa una grave violación de principios de control de acceso.

---

## 🛡️ Recomendaciones

- **Nunca confiar en parámetros del lado cliente** para decidir qué recurso entregar. Se debe validar en backend que el recurso solicitado pertenece al usuario autenticado.
- **Evitar exponer UUIDs o identificadores sensibles** si no son estrictamente necesarios. El hecho de que un identificador sea "difícil de adivinar" no lo hace seguro si está accesible.
- Implementar controles de acceso robustos en el backend, basados en el contexto de sesión y no en parámetros manipulables.
- Registrar accesos a recursos críticos para detectar patrones de abuso o exploración.

---

## 📚 Lecciones aprendidas

- El uso de UUIDs en lugar de IDs incrementales **no mitiga el riesgo de IDOR** si estos son expuestos públicamente.
- La validación de autorización debe realizarse **en cada acceso a recursos sensibles**, y no solo en el login.
- Una API Key mal protegida puede habilitar accesos programáticos a funciones privilegiadas, incrementando el impacto potencial de la explotación.
- **Inspeccionar el código fuente HTML y los enlaces internos** puede revelar identificadores o rutas clave en la aplicación.

---
