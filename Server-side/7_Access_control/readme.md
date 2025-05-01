## 🧠 Access control vulnerabilities and privilege escalation

En esta sección vamos a explicar en profundidad qué son los controles de acceso, por qué son importantes, cuáles son los modelos más comunes, qué formas toma su ruptura (broken access control), y cómo se puede prevenir este tipo de vulnerabilidad tan crítica.

---

### 🔐 ¿Qué es el control de acceso?

El control de acceso es el conjunto de mecanismos que definen qué usuarios pueden realizar determinadas acciones o acceder a ciertos recursos. En aplicaciones web, el control de acceso está fuertemente vinculado a:

- **Autenticación**: verifica la identidad del usuario.
- **Gestión de sesiones**: mantiene esa identidad durante las peticiones HTTP subsecuentes.
- **Control de acceso**: impone las restricciones sobre lo que el usuario autenticado puede hacer.

Una mala implementación de controles de acceso ("broken access control") es una de las vulnerabilidades más comunes y críticas en el desarrollo de software.

---

### 🔖 Modelos de seguridad de control de acceso

# 🔖 Modelos de Seguridad de Control de Acceso

Los modelos de seguridad de control de acceso definen formalmente las reglas mediante las cuales los sistemas determinan si un sujeto (por ejemplo, un usuario) puede acceder a un objeto (por ejemplo, un recurso, archivo o funcionalidad). Elegir el modelo adecuado es clave para implementar políticas de seguridad que equilibren protección, eficiencia y facilidad de gestión.

---

## ✅ Programmatic Access Control (Control de Acceso Programático)
Este modelo no depende de una estructura fija como los roles o grupos, sino que define una **matriz de privilegios** almacenada normalmente en una base de datos. El sistema consulta esta matriz en tiempo real para validar si un usuario puede ejecutar determinada acción sobre un recurso.

### ✨ Ventajas:
- Altamente granular.
- Flexible y personalizable.
- Permite implementar reglas específicas para contextos complejos (por ejemplo: restricciones por horario, ubicación, estado de un proceso, etc.).

### 📆 Ejemplo:
```sql
-- Tabla de privilegios
user_id | recurso     | accion     | permitido
--------|-------------|------------|-----------
1       | /admin      | DELETE     | true
2       | /admin      | DELETE     | false
```
El backend consulta esta matriz antes de ejecutar la acción solicitada.

---

## ✉️ Discretionary Access Control (DAC - Control de Acceso Discrecional)
En este modelo, el **dueño del recurso** tiene la potestad de decidir quién puede acceder a él y en qué medida.

### ✨ Ventajas:
- Muy flexible para entornos colaborativos.
- Fácil de entender.

### ⚠️ Riesgos:
- Difícil de escalar en sistemas grandes.
- Los usuarios pueden cometer errores y otorgar permisos excesivos.

### 📆 Ejemplo:
Un usuario crea un archivo y comparte acceso de lectura con otro usuario. Si se equivoca y da acceso de escritura, podría causar una brecha.

---

## 🏛️ Mandatory Access Control (MAC - Control de Acceso Obligatorio)
Modelo estricto y centralizado. Los usuarios no pueden modificar los permisos. El sistema define reglas globales y etiquetas de seguridad.

### 🔒 Claves del modelo:
- Cada objeto tiene una clasificación (por ejemplo: Confidencial, Secreto, Top Secret).
- Cada sujeto tiene un nivel de autorización.
- El acceso solo se permite si la autorización del sujeto es igual o superior a la clasificación del objeto.

### ✨ Usos comunes:
- Entornos militares o gubernamentales.
- Sistemas que requieren cumplimiento estricto de confidencialidad.

### 📆 Ejemplo:
Un empleado con nivel "Secreto" no podrá acceder a documentos "Top Secret", pero sí a documentos "Confidencial" o "Público".

---

## 📂 Role-Based Access Control (RBAC - Control de Acceso Basado en Roles)
Modelo ampliamente utilizado en entornos empresariales. Se crean **roles** (conjuntos de permisos) y los usuarios son asignados a uno o más roles.

### 📄 Ejemplo de roles:
- `Admin`: Puede gestionar usuarios, editar contenido y ver reportes.
- `Editor`: Puede crear y editar contenido.
- `Viewer`: Solo puede leer contenido.

### ✨ Ventajas:
- Escalable y fácil de administrar.
- Se adapta bien a organizaciones estructuradas por funciones.
- Reduce el riesgo de errores humanos en la asignación de permisos.

### ⚠️ Consideraciones:
- Definir demasiados roles puede hacer que el sistema sea complejo de mantener.

---

## 🔹 Conclusión
Cada modelo tiene sus ventajas y desventajas. En la práctica, muchas aplicaciones modernas utilizan combinaciones de estos enfoques, como RBAC complementado con controles programáticos y lógicas adicionales para ciertos casos especiales.

La clave está en seleccionar el modelo (o combinación) que mejor se adapte a los requisitos de seguridad, escalabilidad y mantenibilidad de la organización.
---

### 🌐 Tipos de controles de acceso

#### ↕️ **Vertical Access Control**
Restringe funcionalidades según el tipo de usuario:

- Un usuario normal no puede acceder al panel de administrador.
- Un moderador puede editar comentarios pero no eliminar usuarios.

#### 🛋 **Horizontal Access Control**
Restringe recursos entre usuarios del mismo tipo:

- Un usuario puede acceder sólo a su perfil: `/user/juan` y no al de `/user/maria`.
- Una app bancaria permite ver solo tus transacciones, no las de otros.

#### ⌛ **Context-Dependent Access Control**
Restringe acciones según el estado de la aplicación:

- No puedes modificar el carrito de compras después de pagar.
- No se puede saltar pasos en un flujo de onboarding.

---

### ❌ Ejemplos de Broken Access Control

#### ⬆️ **Vertical Privilege Escalation**
Un usuario normal accede a funciones administrativas:

```http
GET /admin/deleteUser?username=carlos
```

Si la app no verifica que el usuario tiene privilegios, puede ejecutar esta acción.

#### 🔒 **Funcionalidad sin protección**
Si una página administrativa existe pero no está protegida:

- No hay verificación de roles.
- Está accesible por URL directa.

Ejemplo:
```
https://vulnerable-site.com/admin
```

Incluso si no hay enlaces visibles, el atacante podría descubrir esta ruta por:
- `robots.txt`
- Wordlists + fuerza bruta con Burp Suite, Dirbuster, ffuf, etc.

#### 🛎 **Horizontal Privilege Escalation**
Un usuario accede a los recursos de otro cambiando un ID:

```http
GET /account/details?user_id=112  --> Cambiar por 113
```

Si el backend no verifica que el usuario autenticado es el dueño de `user_id`, puede acceder a información ajena.

---

### 🔒 Prevención de vulnerabilidades de acceso

1. **Verificar roles y permisos en el backend, siempre**.
2. **Nunca confiar en datos enviados por el cliente** (como IDs, roles, flags de admin).
3. **Implementar RBAC o controles programáticos robustos**.
4. **No exponer endpoints sensibles sin protección**.
5. **Auditar código y rutas ocultas o abandonadas (legacy)**.
6. **Realizar pentesting específico de control de acceso**: fuzzing de rutas, manipulación de IDs, tests de roles cruzados.

---

En la próxima sección comenzamos con el primer laboratorio relacionado a Broken Access Control. ¡A practicar!

