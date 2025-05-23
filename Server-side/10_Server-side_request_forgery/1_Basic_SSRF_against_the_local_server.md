# Lab: Basic SSRF against the local server

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---


Accedemos al laboratorio y nos encontramos con una aplicación de shopping:
![image](https://github.com/user-attachments/assets/39f4f36f-1f79-413d-acbf-c62fa79d8939)

Hacemos click en `View details`:
![image](https://github.com/user-attachments/assets/6db305c1-0717-413c-9f7f-8c6e1739b798)

Hacemos click en `Check stock` y vemos que nos devuelve 672 unidades.:
![image](https://github.com/user-attachments/assets/60701930-c148-44da-a71a-feaf1e589110)

Esta captura representa perfectamente el escenario de una vulnerabilidad SSRF clásica y funcional.

`Dato clave`: El valor de stockApi está codificado y apunta a un endpoint interno:
```bash
http://stock.weliketoshop.net:8080/product/stock/check?productId=3&storeId=1
```

Esto indica que el servidor está haciendo una solicitud HTTP saliente a la URL que el cliente define. Esta es la esencia de un SSRF.

Indicadores:
- El parámetro `stockApi` es directamente manipulable por el usuario.

- La respuesta contiene datos obtenidos por el servidor a partir de la URL proporcionada.

Procedemos a explotar la vulnerabilidad intentando acceder a recursos internos, particularmente utilizamos el siguiente payload, el cual buscará acceder al localhost a través del parámetro `stockApi`:
```bash
stockApi=http%3a%2f%2f127.0.0.1
```
Enviamos la solicitud al repeater y realizamos el ataque:
![image](https://github.com/user-attachments/assets/a3ad4a95-6cc8-4996-a9ba-283855cf6540)

Notamos que somos capaces de acceder al localhost, por lo que pudimos explotar la vulnerabilidad `SSRF`. Vemos que tenemos acceso al panel de administración, por lo que ingresamos al mismo buscando su enlace en el código fuente:
![image](https://github.com/user-attachments/assets/fea99248-b429-401e-a03f-bd00e3939ba2)

Para acceder al panel de administración, en este caso el payload url-encoded sería el siguiente:
```bash
stockApi=http%3a%2f%2f127.0.01%2fadmin
```

El servidor accedió al endpoint interno `/admin` como si fuera un usuario autenticado local. Como respuesta se obtiene la interfaz de administración con las opciones para borrar a los usuarios `wiener` y `carlos`.

![image](https://github.com/user-attachments/assets/fb5eb25e-4010-4fd4-b54c-19994d45863b)

Si filtramos por `carlos` en el código fuente, encontraremos el endpoint para eliminar su cuenta, el cual es `/admin/delete?username=carlos`:
![image](https://github.com/user-attachments/assets/02b2c36d-a27f-4527-b1da-6dd4934638b5)

Accedemos a ese endpoint:
![image](https://github.com/user-attachments/assets/8a4f35bc-9b75-4069-8cb8-29c7669d350a)

Vemos que logramos eliminar el usuario `carlos`, por lo que resolvimos el laboratorio. Seguimos la redirección a `/admin` haciendo click en `Follow redirection` para visualizar el banner en el Burp Suite:
![image](https://github.com/user-attachments/assets/f9cc2da2-a230-4c54-925b-92c00022bb4e)


---

---

### ✅ Conclusión

En este laboratorio se demostró una vulnerabilidad **Server-Side Request Forgery** donde el servidor hacía solicitudes HTTP salientes basadas en una entrada controlada por el usuario (parámetro `stockApi`). Al manipular esta entrada, se logró que el servidor accediera a recursos internos como `http://127.0.0.1/admin`, lo que permitió eludir controles de acceso y acceder al panel administrativo. Desde allí, se procedió a eliminar el usuario `carlos`, completando el objetivo del laboratorio.

---

### 🛡️ Recomendaciones

- **Nunca confiar en parámetros proporcionados por el usuario** para construir solicitudes del lado del servidor.
- Implementar listas blancas (`whitelists`) estrictas de dominios válidos o direcciones IP permitidas para solicitudes salientes.
- **Bloquear accesos internos** (como `127.0.0.1`, `localhost`, `169.254.169.254`, etc.) en el firewall de aplicaciones o mediante validación en la capa lógica.
- Registrar y monitorear el comportamiento de servicios que hacen solicitudes salientes, especialmente si reciben URLs externas como entrada.

---

### 📘 Lecciones aprendidas

- Un SSRF permite a un atacante hacer que el servidor realice una solicitud HTTP a un recurso arbitrario, lo que puede llevar al acceso no autorizado o incluso a ejecución de comandos si se encadena con otras vulnerabilidades.
- Es fundamental entender que **el hecho de que el cliente no pueda acceder directamente a un recurso protegido no impide que lo haga indirectamente a través del servidor**, si este actúa como proxy sin restricciones.
- **Codificar correctamente las URLs** es clave para inyectar valores válidos en parámetros como `stockApi`.
- Este tipo de laboratorio refuerza el conocimiento práctico sobre **cómo una mala implementación de lógica de negocio puede llevar a impactos críticos** como acceso a paneles administrativos internos.

---
