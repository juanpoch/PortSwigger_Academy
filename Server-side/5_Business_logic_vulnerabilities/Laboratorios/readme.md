# 📄 Ejemplos comunes de vulnerabilidades lógicas

### 1. Confianza excesiva en controles del lado cliente
- Asumir que la validación en JavaScript es suficiente.
- Un atacante puede simplemente usar herramientas como Burp Proxy para manipular los datos después de que el navegador los haya enviado, pero antes de que se transmitan a la lógica del servidor. Esto inutiliza los controles del lado del cliente.

**Ejemplo**: Descuento aplicado solo si el total > $1000. El atacante modifica el carrito tras aplicar el descuento, dejando solo $100, pero manteniendo el descuento.

[Lab: OS command injection, simple case](1_OS_command_injection_simple_case.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)  

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

