## 🧠 Access control vulnerabilities and privilege escalation

En esta sección vamos a explicar en profundidad qué son los controles de acceso, por qué son importantes, cuáles son los modelos más comunes, qué formas toma su ruptura (broken access control), y cómo se puede prevenir este tipo de vulnerabilidad tan crítica.

---

### 🔐 ¿Qué es el control de acceso?

El control de acceso es el conjunto de mecanismos que definen qué usuarios pueden realizar determinadas acciones o acceder a ciertos recursos. En aplicaciones web, el control de acceso está fuertemente vinculado a:

- **Autenticación**: verifica la identidad del usuario.
- **Gestín de sesiones**: mantiene esa identidad durante las peticiones HTTP subsecuentes.
- **Control de acceso**: impone las restricciones sobre lo que el usuario autenticado puede hacer.

Una mala implementación de controles de acceso ("broken access control") es una de las vulnerabilidades más comunes y críticas en el desarrollo de software.

---

### 🔖 Modelos de seguridad de control de acceso

#### ✅ **Programmatic Access Control**
Un enfoque flexible y granular. Se define una matriz de privilegios (por rol o usuario) almacenada en una base de datos, y el código del backend consulta esa matriz para decidir qué acciones están permitidas.

#### ✉️ **Discretionary Access Control (DAC)**
El usuario "dueño" de un recurso puede decidir quién más puede accederlo. Tiene mucha flexibilidad, pero puede volverse muy complejo de administrar.

#### 🏛️ **Mandatory Access Control (MAC)**
Modelo centralizado (común en entornos militares) donde los usuarios no pueden modificar las reglas de acceso. Todo está definido por clasificación.

#### 📂 **Role-Based Access Control (RBAC)**
Se definen roles con permisos asociados (por ejemplo: "Admin", "Editor", "Viewer"), y los usuarios se asignan a esos roles. Es uno de los modelos más populares en aplicaciones empresariales.

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

