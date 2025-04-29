## 🏦 Vulnerabilidades de Lógica de Negocio (Business Logic Vulnerabilities)

---

# 🔐 ¿Qué son las vulnerabilidades de lógica de negocio?

Las **vulnerabilidades de lógica de negocio** (tambien conocidas como *logic flaws* o *application logic vulnerabilities*) son **fallos en el diseño o implementación de la aplicación** que permiten a un atacante manipular funcionalidades legítimas de forma maliciosa.

Estas fallas no suelen derivarse de errores de programación técnicos como buffer overflows o inyecciones, sino que son consecuencia de **asunciones incorrectas sobre el comportamiento del usuario o del flujo de la aplicación**.

> 💡 Estas vulnerabilidades emergen cuando el sistema **no valida adecuadamente estados no previstos**, permitiendo a los atacantes ejecutar flujos que no deberían ser posibles.

---

# 🔗 Ejemplo simple

Supongamos un sitio de compras que tiene esta regla:

- Solo se puede aplicar un cupón de descuento si el carrito supera los $100.

Pero la validación está solo del lado cliente (JavaScript). Un atacante podría interceptar la solicitud, modificar el total o forzar el uso del cupón desde Burp Suite.

Resultado: descuento aplicado sin cumplir la condición.

---

# 🤔 ¿Cómo surgen?

Las vulnerabilidades de lógica suelen surgir por:

- Asumir que los usuarios solo usarán la app como fue diseñada.
- Validar condiciones críticas **solo en el cliente (JavaScript)**.
- No verificar el estado del sistema entre pasos del flujo.
- Flujos de negocio mal definidos o pobremente documentados.
- Desarrolladores que no conocen toda la aplicación o sus dependencias.

Ejemplo típico:
- Asumir que si un usuario hace clic en "comprar", antes ya pasó por "agregar al carrito". Pero el atacante envía una solicitud forjada para comprar directamente.

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

1. **Saltearse pasos obligatorios en flujos**  
   - Comprar sin pagar.  
   - Usar funcionalidades sin estar logueado.  

2. **Uso indebido de parámetros modificables**  
   - Cambiar `price=10` por `price=1` en una petición.  

3. **Reutilización de tokens / enlaces caducos**  
   - Volver a usar links de reseteo de contraseña.  

4. **Flujos inconsistentes**  
   - Pagar un carrito, luego modificarlo y volver a pagar con el mismo token.  

5. **Manipulación de datos sensibles a nivel de API**  
   - Cambiar el campo `user_id` en una petición PUT para editar el perfil de otro usuario.

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

