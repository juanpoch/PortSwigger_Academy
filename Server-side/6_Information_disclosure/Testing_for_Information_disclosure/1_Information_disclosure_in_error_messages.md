# Lab: Information disclosure in error messages

This lab's verbose error messages reveal that it is using a vulnerable version of a third-party framework. To solve the lab, obtain and submit the version number of this framework.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)  

---


Iniciamos el laboratorio y tenemos una aplicación de shopping:
![image](https://github.com/user-attachments/assets/a1f7c447-6dc6-48b4-8b44-8a358f4dfc0f)

Hacemos click en `View details` en un producto:
![image](https://github.com/user-attachments/assets/5f9f0022-0d86-4760-b311-a9b9ec5ffc3b)


No hay más funcionalidad que esta, el único parámetro que encontramos es `productId=1`, por lo que procedemos a cambiar los valores del parámetro usando el `Repeater` y vemos que cambian los productos:
![image](https://github.com/user-attachments/assets/26e847c1-0938-484c-979c-69a90e6cafc8)

Ingresamos un número muy grande y recibimos el mensaje `Not Found`:
![image](https://github.com/user-attachments/assets/30c289ea-5b5f-4c3f-8981-16403f0f482f)

Procedemos a ingresarle una cadena arbitraria al parámetro `productId` para analizar cómo reacciona y vemos un mensaje `500 Internal Server Error`:
![image](https://github.com/user-attachments/assets/3f144f13-b941-4ff8-9ec7-3ce292368eeb)

Si hacemos scroll down sobre la respuesta, vemos que nos revela la versión de Apache `Apache Struts 2 2.3.31`:
![image](https://github.com/user-attachments/assets/00848add-9305-4266-93a9-cb20716200b4)

Por lo que hacemos click en `submit solution` y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/71fbee61-d4fa-486c-9f8a-f8ce58d52a9b)

![image](https://github.com/user-attachments/assets/71a2297b-33a8-4164-a49e-3904ad8dbe6b)

---

---

### ✅ Conclusión

Este laboratorio demuestra una **vulnerabilidad de información expuesta** (Information Disclosure) a través de **mensajes de error verbosos**.

- El servidor devuelve un **stack trace completo** al recibir un valor inesperado en el parámetro `productId`, lo cual es un mal manejo de errores.
- El error reveló la versión exacta del framework utilizado en el backend: `Apache Struts 2 2.3.31`.
- Esta información es **altamente sensible**, ya que versiones específicas de Struts (como la mencionada) han sido históricamente vulnerables a **RCE (Remote Command Execution)** como ocurrió con **CVE-2017-5638**.

---

### 🛡️ Recomendaciones

- **Deshabilitar mensajes de error detallados** en entornos productivos.
- Usar **mensajes genéricos** del tipo `"Internal Server Error"` y registrar el error completo solo en logs internos.
- **Actualizar frameworks y tecnologías de terceros**. Struts 2.3.31 es una versión obsoleta con vulnerabilidades conocidas.
- Implementar un **WAF (Web Application Firewall)** que pueda detectar y bloquear tráfico malicioso, como entradas inválidas que desencadenen errores del backend.
- Validar correctamente los tipos de entrada. En este caso, se esperaba un número entero, pero el sistema no rechazó correctamente una cadena malformada.
- Evitar devolver al cliente cualquier contenido del **stack trace** o información del entorno de ejecución (como versiones, rutas internas o dependencias).

---

### 🧠 Lecciones aprendidas

- A veces, **una vulnerabilidad de bajo impacto aparente**, como un mensaje de error, puede ser la clave para una explotación mayor.
- Este tipo de errores son **comunes en entornos donde se despliega código en producción sin limpiar configuraciones de debugging**.
- En un entorno real, este hallazgo sería **una puerta de entrada para identificar exploits públicos** y lanzar un ataque más serio (como RCE).

---










