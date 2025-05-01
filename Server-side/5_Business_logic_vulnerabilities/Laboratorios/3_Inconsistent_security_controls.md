# Lab: Inconsistent security controls

This lab's flawed logic allows arbitrary users to access administrative functionality that should only be available to company employees. To solve the lab, access the admin panel and delete the user `carlos`.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)

---

## 🛒 Análisis inicial

Iniciamos el lab y nos encontramos con una aplicación de compras:

![image](https://github.com/user-attachments/assets/ed2ce9d5-9e31-44f5-8d1b-a49069a46e65)

Como sabemos que debemos acceder al panel de administración, intentamos manualmente acceder al endpoint `/admin`:

![image](https://github.com/user-attachments/assets/1cbf9676-64dd-4512-afef-085ef7c2ca85)

Nos devuelve un mensaje indicando que el acceso está limitado a usuarios bajo el dominio `dontwannacry.com`.

---

## 📬 Registro de usuario

Accedemos al formulario de registro mediante `Register`:

![image](https://github.com/user-attachments/assets/5ff0d6df-20de-4f84-a442-a1923e03d4ba)

Intentamos registrarnos como `test@dontwannacry.com`, pero el sistema requiere validación por correo electrónico:

![image](https://github.com/user-attachments/assets/7b96419e-6212-4597-b845-4364ad0c82cc)

Validamos cuál es nuestra casilla legítima a través del botón `Email client`:

![image](https://github.com/user-attachments/assets/ce0cbd4e-c868-4534-83be-f1e2b62427f3)

Nos registramos con nuestra casilla legítima:  
📧 `attacker@exploit-<ID>.exploit-server.net`

![image](https://github.com/user-attachments/assets/0b83fb74-de7e-4b06-b7e1-b705428fdd3e)

Recibimos un email de activación:

![image](https://github.com/user-attachments/assets/54b82d60-23e7-4ada-84d0-5e2630be8037)

Activamos la cuenta, accedemos a `My account` y luego hacemos clic en `Update email`.

---

## 🕳️ Explotación: Lógica inconsistente

Ingresamos `test@dontwannacry.com` como nuevo correo y observamos que el sistema nos permite el cambio sin ninguna validación adicional:

![image](https://github.com/user-attachments/assets/4178470f-3949-4444-bd69-de102e7a0b6c)

Una vez cambiado, se revela el panel de administración directamente desde nuestro dashboard:

![image](https://github.com/user-attachments/assets/9e50f1e6-41b8-4664-8721-93a4edab450d)

Desde este panel podemos eliminar usuarios. Eliminamos a `carlos` y resolvemos el laboratorio:

![image](https://github.com/user-attachments/assets/d6161d79-ec41-4f70-9585-b20998dcef40)

---

## ✅ Conclusión

El sistema implementa una lógica insegura que **confía ciegamente en el dominio del email del usuario** como mecanismo de autorización.

Esto permitió cambiar el correo electrónico a uno autorizado y acceder a funcionalidades administrativas restringidas.

---

## 🛡️ Recomendaciones

- **Nunca usar valores como el dominio de un correo electrónico como único criterio de autorización.**
- Implementar roles y permisos a nivel de servidor y verificar cada acción sensible según el contexto de autenticación del usuario.
- Validar cualquier cambio sensible con autenticación reforzada o autorización basada en sesiones y tokens confiables.
