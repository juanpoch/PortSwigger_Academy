# 🛡️ Cómo encontrar y probar vulnerabilidades XSS almacenadas

Se pueden encontrar muchas vulnerabilidades XSS almacenadas utilizando el escáner de vulnerabilidades web de **Burp Suite**.

Analizar manualmente las vulnerabilidades XSS almacenadas puede ser complicado. Es necesario analizar todos los **puntos de entrada relevantes** a través de los cuales los datos controlables por el atacante pueden acceder al procesamiento de la aplicación, y todos los **puntos de salida** donde dichos datos podrían aparecer en las respuestas de la aplicación.

---

## 📥 Puntos de entrada al procesamiento de la solicitud

- Parámetros u otros datos dentro de la **cadena de consulta de URL** y el **cuerpo del mensaje**.
- La **ruta del archivo URL**.
- **Encabezados de solicitud HTTP** que podrían no ser explotables en relación con XSS reflejado.
- Cualquier **ruta fuera de banda** mediante la cual un atacante pueda enviar datos a la aplicación.

> Las rutas fuera de banda dependen completamente de la funcionalidad de la aplicación:
>
> - Una app de **correo web** procesará datos recibidos en correos electrónicos.
> - Una app que muestra un **feed de Twitter** podría procesar datos contenidos en tuits.
> - Un **agregador de noticias** incluirá datos procedentes de otros sitios web.

---

## 📤 Puntos de salida

Son **todas las posibles respuestas HTTP** que se devuelven a **cualquier tipo de usuario** de la aplicación en cualquier situación.

---

## 🔎 Primer paso: encontrar vínculos entre puntos de entrada y salida

El objetivo es **detectar lugares donde los datos enviados a un punto de entrada aparecen en una salida**.

⚠️ **Dificultades comunes:**

- Los datos enviados a **cualquier punto de entrada** podrían aparecer en **cualquier punto de salida**.
  - Ej: un nombre de usuario podría mostrarse en un registro de auditoría visible solo a ciertos roles.
- Los datos **almacenados pueden sobrescribirse** por otras acciones del sistema.
  - Ej: una función de búsqueda con historial que cambia constantemente.

> Para hacer esto de forma exhaustiva, deberías probar cada permutación por separado:
> - Introducir un valor específico en un punto de entrada.
> - Navegar al punto de salida.
> - Verificar si aparece reflejado.

😅 Este método no es práctico en aplicaciones grandes.

---

## ✅ Enfoque realista

1. Trabajar sistemáticamente con cada punto de entrada.
2. Introducir un **valor de prueba único**.
3. Monitorizar las respuestas de la aplicación para detectar si el valor aparece.
4. Priorizar funciones típicas como comentarios, publicaciones, perfiles, etc.
5. Confirmar si el dato reflejado es parte de un almacenamiento persistente o reflejado inmediato.

---

## 🧪 Probar cada vínculo con cargas útiles XSS

Una vez identificado un vínculo entre entrada y salida:

- Determinar el **contexto HTML/JS** donde aparece el dato.
- Probar con **cargas útiles XSS adecuadas** al contexto.
  - Igual que en la metodología de detección de **XSS reflejado**.
