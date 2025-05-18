# 🧩 Insecure Deserialization 


**Serialization** es el proceso de convertir estructuras de datos complejas (como objetos con sus atributos) en un formato plano, que puede ser transmitido como un flujo de bytes.

Esto permite, por ejemplo:
- Guardar objetos en archivos, bases de datos o memoria compartida.
- Enviar objetos por red o entre componentes de una aplicación.

✅ Lo importante es que **el estado del objeto se conserva**: sus propiedades y valores quedan embebidos en el flujo serializado.

---

## ↺ Deserialización

**Deserialization** es el proceso inverso: restaurar un objeto desde su forma serializada.

Permite que la lógica de una aplicación trabaje con ese objeto como si lo hubiera creado directamente.

---

## 💡 Términos equivalentes

Dependiendo del lenguaje:
- En **Ruby** se llama `marshalling`
- En **Python** se llama `pickling`
- En **Java** y **PHP**, simplemente `serialization`

---

## ⚠️ ¿Qué es Insecure Deserialization?

Se habla de **insecure deserialization** cuando una aplicación **deserializa datos controlados por el usuario**. Esto permite que un atacante modifique objetos serializados para ejecutar acciones maliciosas.

Incluso puede reemplazar un objeto esperado por uno de **una clase totalmente diferente**, lo que también se conoce como **object injection**.

🔒 El ataque puede ejecutarse durante el proceso de deserialización mismo, **sin que el objeto malicioso tenga que ser utilizado directamente por la aplicación**.

---

## ⛔️ Ejemplo de código vulnerable en PHP

```php
// Supongamos que se recibe el objeto desde una cookie o parámetro POST
$user = unserialize($_COOKIE['user']);
```

Un atacante podría enviar un objeto serializado modificado como:

```php
O:8:"Exploit":0:{}
```

Si la clase `Exploit` existe y tiene un método `__wakeup()` o `__destruct()` malicioso, se ejecutará.

---

## 💣 Impacto de la vulnerabilidad

- **Remote Code Execution (RCE)**  ✔
- **Privilegios elevados**
- **Acceso arbitrario a archivos**
- **Denegación de servicio (DoS)**

El atacante puede reutilizar código legítimo de la aplicación para lograr ejecución arbitraria: esto se conoce como **gadget chains**.

---

## 🥶 Por qué ocurre esta vulnerabilidad?

- Subestimar el riesgo de deserializar datos del usuario.
- Implementar validaciones **después** de deserializar (ya es tarde).
- Suponer que los datos serializados en binario no pueden ser manipulados.
- La complejidad de las dependencias y librerías hace que existan miles de clases disponibles (y explotables).

---

## 🔧 Ejemplo de ataque en Java

Si una app usa:
```java
ObjectInputStream in = new ObjectInputStream(request.getInputStream());
MyObject obj = (MyObject) in.readObject();
```

Un atacante puede enviar un objeto serializado de una clase diferente, que al deserializarse **ejecute código arbitrario** al invocar métodos como `readObject()`, `finalize()` o `readResolve()`.

---

## 📆 Casos reales

- [CVE-2015-4852](https://nvd.nist.gov/vuln/detail/CVE-2015-4852) - Vulnerabilidad de deserialización en Oracle WebLogic.
- Frameworks como Apache Commons Collections, Spring, y Struts han sido afectados por gadget chains reutilizables.

---

## 🔒 Prevención

- ❌ **Evitar la deserialización de datos no confiables**.
- ✉️ Si es inevitable, **verificar integridad** con firmas digitales antes de deserializar.
- ⚖️ Usar mecanismos personalizados de serialización (evitar los métodos por defecto).
- 🔀 Filtrar clases permitidas en deserialización (whitelisting).
- 🔎 Estar atento a las dependencias y gadget chains conocidas.

> ⚠️ **Recordá:** la vulnerabilidad está en deserializar entrada del usuario, **no** en las gadget chains. No sirve eliminar gadgets si la entrada sigue siendo deserializada.

---

## 🔍 Recursos recomendados

- [PortSwigger - Insecure Deserialization](https://portswigger.net/web-security/deserialization)
- [OWASP - Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [PayloadsAllTheThings - Insecure Deserialization](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization)
- [YSoSerial - Java gadget chain generator](https://github.com/frohoff/ysoserial)

---


