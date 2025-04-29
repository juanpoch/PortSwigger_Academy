## 🏦 Guía Completa: Vulnerabilidades de Lógica de Negocio (Business Logic Vulnerabilities)

---

# 🔐 ¿Qué son las vulnerabilidades de lógica de negocio?

Las **vulnerabilidades de lógica de negocio** (tambien conocidas como *logic flaws* o *application logic vulnerabilities*) son **fallos en el diseño o implementación de la aplicación** que permiten a un atacante manipular funciones lítimas de forma maliciosa.

Estas fallas no suelen derivarse de errores de programación técnicos como buffer overflows o inyecciones, sino que son consecuencia de **asunciones incorrectas sobre el comportamiento del usuario o del flujo de la aplicación**.

> 💡 Estas vulnerabilidades emergen cuando el sistema **no valida adecuadamente estados no previstos**, permitiendo a los atacantes ejecutar flujos que no deberían ser posibles.

---

# 🔗 Ejemplo simple

Supongamos un sitio de compras que tiene esta regla:

- Solo se puede aplicar un cupón de descuento si el carrito supera los $100.

Pero la validación está solo del lado cliente (JavaScript). Un atacante podría interceptar la solicitud, modificar el total o forzar el uso del cupón desde Burp Suite.

Resultado: descuento aplicado sin cumplir la condición.

---

# 🚀 Impacto de estas vulnerabilidades

Depende directamente del área afectada. Algunos ejemplos:

| 🌐 Afecta a... | 📉 Posibles consecuencias |
|-------------|--------------------------|
| Autenticación | Acceso sin login, escalación de privilegios |
| Transacciones financieras | Fraude, duplicación de saldo, descuentos indebidos |
| Procesos administrativos | Evasiones de validación, básqueda de estados inconsistentes |
| Límites de uso | Eludir restricciones de cuota, burlar mecanismos anti-spam |

Incluso si no hay beneficio directo, pueden usarse para **dañar el negocio** (por ejemplo, pedidos gratuitos, anulación de pagos, abuso de devoluciones).

---

# 📄 Ejemplos comunes de vulnerabilidades lógicas

### 1. Confianza excesiva en controles del lado cliente
- Asumir que la validación en JavaScript es suficiente.
- Un atacante puede interceptar la petición con Burp Suite y modificar valores como precios, cantidad o aplicar descuentos indebidos.

**Ejemplo**: Descuento aplicado solo si el total > $1000. El atacante modifica el carrito tras aplicar el descuento, dejando solo $100, pero manteniendo el descuento.

### 2. No gestionar entrada no convencional
- Enviar valores negativos, enormes o cadenas anómalas.
- Ej: pasar `-1000` como cantidad en una transferencia. La condición `if (amount <= balance)` se cumple, transfiriendo fondos al atacante.

### 3. Suponer que los usuarios siempre completan pasos del flujo
- El atacante puede omitir pasos con **navegación forzada**, por ejemplo, ir directo al paso 3 sin completar el paso 2 (como saltar la autenticación 2FA).

### 4. Eliminar parámetros obligatorios
- Creer que siempre se enviarán todos los campos de un formulario.
- El atacante puede omitir campos, alterar la ruta del código y obtener respuestas inesperadas o comportamiento privilegiado.

### 5. Defectos específicos del dominio
- En tiendas: aplicar descuentos sin cumplir condiciones, manipular códigos de promoción, o explotar errores en cálculo de precios.

**Ejemplo**: El sistema aplica 10% de descuento por compras > $1000, pero el atacante reduce el carrito antes de pagar sin que el sistema lo detecte.

### 6. Proveer un oráculo de cifrado
- El sistema cifra datos controlados por el usuario y devuelve el resultado.
- El atacante usa esto para generar tokens válidos o manipular autenticación.

### 7. Discrepancias en el parser de emails
- El sistema analiza emails para validar dominios confiables.
- El atacante usa técnicas de codificación para engañar al parser y obtener acceso privilegiado usando un dominio falso.

---

# 🛡️ Prevención de vulnerabilidades lógicas

### 1. Comprensión total del dominio
- Todo el equipo de desarrollo y QA debe entender el **modelo de negocio**.
- Identificar los **objetivos del atacante** dentro de ese modelo.

### 2. Validar SIEMPRE del lado servidor
- Toda condición crítica (precio mínimo, roles, límites) debe ser **controlada y reforzada del lado backend**.

### 3. Documentar flujos de negocio
- Crear diagramas de flujo claros de todos los procesos.
- Documentar las **asunciones** en cada paso.

### 4. Hacer pruebas de integración lógica
- Probar pasos fuera de orden, manipular parámetros y repetir transacciones.
- Intentar **combinar módulos que no deberían interactuar directamente**.

### 5. Revisiones cruzadas de código
- Que otros desarrolladores revisen componentes ajenos.
- Preguntarse: “¿Qué pasa si un atacante usa esto de forma no prevista?”

---

# 🧠 Conclusión

Las vulnerabilidades de lógica de negocio **no son errores técnicos clásicos**, sino defectos en la manera en que se implementan las reglas del negocio.

- **No suelen ser detectadas por escáners automáticos**.
- Requieren comprensión profunda de la aplicación y del negocio.
- Su impacto puede ir desde lo trivial hasta ataques devastadores.

> 💡 Por eso son un blanco ideal para **bug bounty hunters** y pentesters que hagan pruebas manuales.

Fomentar el pensamiento crítico, la revisión cruzada y la validación exhaustiva de flujos es la mejor forma de reducir este tipo de errores.

