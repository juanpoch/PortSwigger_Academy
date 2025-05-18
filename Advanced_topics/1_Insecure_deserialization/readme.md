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
<?php

// Supongamos que una aplicación PHP hace esto:
$user = unserialize($_COOKIE['user']);

/*
✨ Explicación paso a paso:

1. ¿Qué hace `unserialize()`?
   - Convierte una cadena serializada (texto) en un objeto PHP real.
   - Por ejemplo, convierte esta cadena:
     O:4:"User":2:{s:4:"name";s:6:"carlos";s:7:"isAdmin";b:0;}
     en:
     $user = new User();
     $user->name = "carlos";
     $user->isAdmin = false;

2. ¿Cuál es el riesgo?
   - Si la cadena proviene de una fuente **controlada por el usuario** (como una cookie), un atacante puede manipularla.

3. Supongamos que un atacante envía:
   O:7:"Exploit":0:{}
   - `O:7:"Exploit"` indica que se va a deserializar un objeto de clase `Exploit`.
   - `0:{}` indica que no tiene atributos.

4. Si existe una clase `Exploit` en el código del servidor como esta:
*/

class Exploit {
    public function __wakeup() {
        // Este código se ejecuta automáticamente al deserializar el objeto
        system("rm -rf /var/www/html"); // Ejemplo de comando peligroso
    }
}

/*
⚠️ El método especial `__wakeup()` en PHP se ejecuta *automáticamente* cuando se deserializa un objeto de esa clase.

Lo mismo ocurre con `__destruct()` (cuando el objeto es destruido), `__call()`, o `__toString()` si son invocados indirectamente.

5. Por lo tanto, al deserializar un objeto de la clase `Exploit`, PHP ejecuta el código del método `__wakeup()` *sin que el desarrollador lo haya llamado*. Esto se conoce como **object injection**.

6. Resultado: el atacante logra ejecutar código arbitrario simplemente enviando una cookie con un objeto manipulado.

✅ Conclusión:
Nunca deberías usar `unserialize()` con datos controlados por el usuario sin verificar que sean seguros.
*/
```

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

## 📊 Comparativa de formatos de serialización por lenguaje

| Lenguaje    | Método de serialización | Formato             | Legible para humanos | Soporta clases/objetos | ¿Peligroso si se deserializa entrada del usuario? |
|-------------|--------------------------|----------------------|-----------------------|------------------------|--------------------------------------------------|
| **PHP**     | `serialize()` / `unserialize()` | Texto estructurado | Parcialmente           | ✅ Sí (con atributos y clases) | ✅ Muy peligroso (`__wakeup()`, `__destruct()`)     |
| **Python**  | `pickle` / `cPickle`      | Binario              | ❌ No                  | ✅ Sí (estructura + comportamiento) | ✅ Muy peligroso                                     |
| **Java**    | `Serializable` / `readObject()` | Binario (con cabecera `AC ED`) | ❌ No              | ✅ Sí                   | ✅ Muy peligroso (gadget chains)                    |
| **Ruby**    | `Marshal.dump` / `load`   | Binario              | ❌ No                  | ✅ Sí                   | ✅ Peligroso                                         |
| **.NET**    | `BinaryFormatter`         | Binario              | ❌ No                  | ✅ Sí                   | ✅ Muy peligroso                                     |
| **JSON**    | `json.dumps()` / `loads()`| Texto plano (UTF-8)  | ✅ Sí                  | ❌ Solo datos (sin métodos/clases) | ⚠️ Bajo (solo si se evalúa maliciosamente)         |
| **XML**     | Variado (`SimpleXML`, DOM) | Texto plano (marcado) | ✅ Sí                | ❌ Solo estructura        | ⚠️ Bajo (riesgo si se usa con `XXE`)                |

---

### 🧠 Observaciones

- Los formatos binarios suelen ser más difíciles de detectar y manipular, pero **igual de explotables**.
- Los formatos de texto como JSON o XML **no representan un riesgo de deserialización insegura por sí solos**, pero pueden ser peligrosos si son usados de forma insegura (e.g., `eval()` en JSON, o mal manejo de entidades externas en XML).
- El **peligro real surge cuando se deserializa un objeto completo**, no solo sus datos.

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


