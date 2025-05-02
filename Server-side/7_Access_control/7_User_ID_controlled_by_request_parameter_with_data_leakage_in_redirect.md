# Lab: User ID controlled by request parameter with data leakage in redirect

This lab contains an access control vulnerability where sensitive information is leaked in the body of a redirect response.

To solve the lab, obtain the API key for the user `carlos` and submit it as the solution.

You can log in to your own account using the following credentials: `wiener:peter`

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---


Accedemos al laboratorio y nos encontramos con una aplicación de shopping:
![image](https://github.com/user-attachments/assets/1b7afa68-d3d8-4fdf-84f5-8d3dba151c23)

Nos dirigimos al panel de autenticación mediante el botón `My account`:
![image](https://github.com/user-attachments/assets/6d190589-958e-4e40-9d8a-41bb9411271e)

Nos autenticamos con nuestras credenciales `wiener:peter` y capturamos el tráfico con `Burp Suite` para analizar el flujo:
![image](https://github.com/user-attachments/assets/654702c0-0aa0-4313-8917-c9d19e20b5ab)

Esta es una típica petición `POST` de autenticación donde se tramitan los parámetros en el cuerpo de la solicitud. El servidor nos responde con un `302 Redirect` hacia el endpoint `/my-account?id=wiener`.

Accedemos al endpoint `/my-account?id=wiener`:
![image](https://github.com/user-attachments/assets/13c5a647-13fd-44ee-b5fb-5435a4b4ec76)

Enviamos esta petición al `Repeater` y cambiamos el valor del parámetro `id=wiener` por `id=carlos`:
![image](https://github.com/user-attachments/assets/843da7cb-65aa-484c-97b8-e30c98e39b41)

Esta captura muestra un caso clásico de fuga de información en una redirección, relacionada con un control de acceso incorrecto:

- Se hace un GET `/my-account?id=carlos`, lo que sugiere un intento de acceso a la cuenta de otro usuario.

- La respuesta es un `HTTP 302 Found` que redirige al usuario a `/login`, indicando que no tiene permisos para ver la página.

- Sin embargo, la respuesta HTML contiene información sensible: el `id=carlos` sigue visible y queda reflejado en el contenido servido.

Filtramos por `carlos` en la respuesta del servidor:
![image](https://github.com/user-attachments/assets/4de0602f-dc36-4611-8316-a0bfe6cbce06)

Esta búsqueda muestra claramente una vulnerabilidad de tipo IDOR en su forma más peligrosa: acceso directo a datos sensibles de otro usuario mediante manipulación de un parámetro URL.

Esta es una vulnerabilidad crítica de control de acceso horizontal.

Procedemos a resolver el laboratorio ingresando el valor de la API Key de carlos `nSnrJnIynhZG0X6bFoVFQ5YS8RV1YWYx`:
![image](https://github.com/user-attachments/assets/b99db88b-455c-468e-a8d2-de973fdb6b6e)


---

# ✅ Comentarios finales

## 🔎 Análisis general del laboratorio

Este laboratorio demuestra un caso de **IDOR** en combinación con una **fuga de información sensible a través de una respuesta de redirección**.

Aunque el sistema detecta que el usuario no tiene permiso para acceder a la cuenta de otro usuario (`/my-account?id=carlos`) y redirige correctamente al login, **el cuerpo de la respuesta contiene datos sensibles antes de la redirección efectiva**, entre ellos la API Key del usuario `carlos`.

Esto demuestra una implementación insegura del control de acceso: el servidor debería validar los permisos antes de generar contenido, no después. De lo contrario, incluso si se impide el acceso "visual", la fuga de datos ocurre de todos modos.

## 🚨 Falla explotada

- **IDOR:** Acceso directo a la información de otro usuario mediante manipulación del parámetro `id`.
- **Fuga de datos en redirección:** A pesar de la redirección, el cuerpo HTML ya contenía la API Key del usuario objetivo (`carlos`).

## 🛡️ Recomendaciones

- Validar que el usuario autenticado tenga permiso para acceder al recurso solicitado **antes de generar cualquier contenido en la respuesta**.
- Asegurarse de que las respuestas de redirección no incluyan ningún contenido sensible en su cuerpo.
- Implementar un sistema de control de acceso centralizado en el backend (por ejemplo, basado en sesiones y roles).
- Monitorear logs de acceso para detectar patrones de manipulación de parámetros (`id`, `userId`, etc).

## 🧠 Lecciones aprendidas

- **Una redirección no equivale a protección:** Redirigir a un usuario no autorizado no es suficiente si ya generaste contenido sensible en la respuesta.
- **El orden de las validaciones importa:** La validación de permisos debe realizarse antes de cualquier renderizado del contenido.
- **Las vulnerabilidades IDOR no dependen del tipo de identificador:** Ya sea un nombre de usuario, ID numérico o UUID, si el sistema confía en el cliente para acceder a recursos, sigue siendo vulnerable.

