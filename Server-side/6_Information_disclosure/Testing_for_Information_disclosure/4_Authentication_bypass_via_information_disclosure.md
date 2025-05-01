# Lab: Authentication bypass via information disclosure

This lab's administration interface has an authentication bypass vulnerability, but it is impractical to exploit without knowledge of a custom HTTP header used by the front-end.

To solve the lab, obtain the header name then use it to bypass the lab's authentication. Access the admin interface and delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 


---


Iniciamos el laboratorio y tenemos la app de shopping, accedemos a los endpoints interceptando con Burp Suite y buscando comentarios sin encontrar nada:
![image](https://github.com/user-attachments/assets/985d86fd-5058-4134-b062-55e8560b5d9c)

Nos dirigimos a `My account` y nos logueamos con nuestras credenciales `wiener:peter`, buscando comentarios no obtenemos match:
![image](https://github.com/user-attachments/assets/b7cf1e5a-91e4-4ac9-a0ed-30b990e8eb0f)

No encontramos ningún comentario ni links ocultos.

Procedemos a buscar el panel de administración, vamos a realizar un ataque de fuerza bruta al endpoint raíz `/` utilizando `Burp Intruder` y la wordlist `common.txt` que en mi caso lo tengo en la ruta `/usr/share/SecLists/Discovery/Web-Content/common.txt`:

![image](https://github.com/user-attachments/assets/841608f1-9e74-4bdd-a914-8855e3709297)

Vemos que el endpoint `/admin` nos arroja un resultado `401 Unauthorized`:
![image](https://github.com/user-attachments/assets/11d821de-b302-4a0f-aa4f-26a598af7271)

Vemos que el acceso al panel de administración sólo está permitido para usuarios locales:
![image](https://github.com/user-attachments/assets/8643e174-8fb2-4d7c-924e-5d631b392f54)

Utilizamos la cabecera `X-Forwarded-For: 127.0.0.1` para hacerle creer al servidor que venimos de una IP local:
![image](https://github.com/user-attachments/assets/059375c9-e84b-4cab-b10d-c153d0ad038b)

Vemos que evidentemente el servidor está utilizando otro parámetros para saber si el usuario proviene del localhost.

Probamos acceder al endpoint mediante todos los verbos HTTP (`GET`, `POST`, `OPTIONS`, `PUT`, `PATCH`, `HEAD`, `TRACE`) sin éxito hasta que notamos que la respuesta es diferente cuando accedemos mediante `TRACE`:
![image](https://github.com/user-attachments/assets/e9ca5c2c-15b9-4c6b-af75-83b7c704e0c9)

Esta captura muestra un grave caso de divulgación de información a través del método HTTP TRACE habilitado — conocido como una mala práctica de seguridad, especialmente cuando se usa en combinación con encabezados como `X-Custom-IP-Authorization`.

- El método TRACE está diseñado para propósitos de diagnóstico: devuelve en la respuesta exactamente lo que se recibió en la solicitud.

- En este caso, la respuesta incluye todos los headers reflejados, lo que confirma que el servidor tiene TRACE habilitado.


Con respecto al uso de `X-Custom-IP-Authorization`, esto indica que el servidor está procesando este header especial, posiblemente utilizado para validar la identidad del cliente por IP, como:
```java
if request.getHeader("X-Custom-IP-Authorization") == "127.0.0.1":
    // permitir acceso administrativo
```

Algunos servidores permiten el acceso administrativo si la IP de origen es `127.0.0.1`. Si se confía en el valor de `X-Custom-IP-Authorization` sin validación, podríamos hacer spoofing de IP utilizando el siguiente header:
```http
X-Custom-IP-Authorization: 127.0.0.1
```

Inyectamos el header y observamos que obtuvimos acceso al panel de administración:
![image](https://github.com/user-attachments/assets/5f7ea79f-2bad-4cd4-a892-09d7127336fc)

Si filtramos por `carlos` observamos el endpoint para eliminar su cuenta en el código fuente:
![image](https://github.com/user-attachments/assets/eb2945ab-429b-4705-8432-0b5ed26b2ab1)

Accedemos al endpoint para eliminar la cuenta de `carlos` y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/62d277f3-6489-419d-9512-0818db6648d9)

![image](https://github.com/user-attachments/assets/13bd2522-0ca5-4d20-adbe-9f485de484f1)

---

## ✅ Conclusión

Se explotó una vulnerabilidad de **divulgación de información** combinada con una mala configuración del servidor, la cual reveló un **header personalizado sensible (`X-Custom-IP-Authorization`)** mediante una solicitud TRACE. Este header permitió realizar un **bypass de autenticación** y acceder al panel de administración sin credenciales válidas, lo cual derivó en el acceso y eliminación de usuarios arbitrarios.

## 🛡️ Recomendaciones

- **Deshabilitar el método HTTP TRACE** en producción, ya que puede reflejar información sensible y facilitar ataques de tipo XST (Cross Site Tracing).
- **No confiar en headers personalizados como `X-Custom-IP-Authorization`** para controles de acceso sin validación adicional.
- **Implementar controles de acceso en el backend basados en sesiones autenticadas**, y no únicamente en valores manipulables por el cliente.
- Validar y registrar el uso de métodos HTTP inusuales como TRACE, OPTIONS, etc., como parte de la estrategia de defensa en profundidad.

## 📚 Lecciones aprendidas

- El método TRACE puede ser utilizado para revelar información sensible como headers personalizados, lo cual puede derivar en vulnerabilidades críticas.
- Los headers HTTP son fácilmente modificables por el cliente; **nunca deben utilizarse como único mecanismo de autenticación o autorización**.
- La observación cuidadosa de pequeñas diferencias en el comportamiento del servidor puede revelar vectores de ataque sutiles.
- La combinación de múltiples errores de bajo impacto puede resultar en una vulnerabilidad crítica (en este caso: TRACE + cabecera no autenticada).












