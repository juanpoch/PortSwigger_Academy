# 📄 Ejemplos comunes de vulnerabilidades lógicas

### 1. Confianza excesiva en controles del lado cliente
- Asumir que la validación en JavaScript es suficiente.
- Un atacante puede simplemente usar herramientas como Burp Proxy para manipular los datos después de que el navegador los haya enviado, pero antes de que se transmitan a la lógica del servidor. Esto inutiliza los controles del lado del cliente.

**Ejemplo**: Descuento aplicado solo si el total > $1000. El atacante modifica el carrito tras aplicar el descuento, dejando solo $100, pero manteniendo el descuento.

[Lab: Excesive trust in client-side controls](1_Excessive_trust_in_client-side_controls.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)  

### 2 🧐 Fallos al manejar entradas no convencionales

Uno de los objetivos fundamentales de la lógica de negocio en cualquier aplicación web es **restringir la entrada del usuario a valores que respeten las reglas del negocio**. Esto no se limita a validar el tipo de dato (por ejemplo, que sea un número entero), sino a validar si el valor en sí **tiene sentido desde la perspectiva del negocio**.

Muchas aplicaciones incluyen restricciones numéricas en su lógica para evitar escenarios indeseados, como:

- Comprar más unidades de las disponibles en stock.
- Realizar transferencias por encima del saldo disponible.
- Activar procesos logísticos antes de que se cumplan ciertos umbrales.
- Aplicar descuentos únicamente bajo condiciones específicas.

## 📆 Ejemplo: compra en una tienda online

Supongamos que una tienda online permite seleccionar la cantidad de unidades a comprar de un producto. Si bien técnicamente se puede enviar **cualquier número entero** al servidor, la lógica debería impedir compras **por encima del stock disponible** o cantidades absurdas (como `-1000`).

Un fallo común ocurre cuando el backend no valida adecuadamente estos valores. Aunque la interfaz web sí puede tener controles (`input[type="number"]`, validaciones con JavaScript, etc.), **un atacante puede usar herramientas como Burp Suite para modificar manualmente los valores enviados** y testear cómo se comporta el servidor.

## 💸 Caso realista: transferencia bancaria

Considerá el siguiente fragmento de código en un sistema de transferencias entre cuentas bancarias:

```php
$transferAmount = $_POST['amount'];
$currentBalance = $user->getBalance();

if ($transferAmount <= $currentBalance) {
    // Transferencia permitida
} else {
    // Fondos insuficientes
}
```

A simple vista parece correcto, pero si no se valida que `$transferAmount` **sea mayor a cero**, un atacante podría enviar un valor negativo como `-1000`. El servidor interpretaría:

```php
if (-1000 <= 5000) { // true
```

Esto **pasa la validación**, y si la lógica no fue escrita cuidadosamente, el resultado podría ser que el servidor realice una transferencia **inversa**, acreditando al atacante $1000 desde la cuenta víctima. Esta es una falla grave de lógica empresarial.

---

## 🧪 Pruebas de entradas no convencionales

Al realizar un pentest o auditoría de seguridad, es fundamental **salirse de los casos normales de uso** y testear cómo la aplicación reacciona ante datos inesperados. Esto incluye:

- Números excesivamente altos (`999999999`) o negativos (`-999`).
- Strings extremadamente largos (miles de caracteres en campos de texto).
- Tipos de datos inesperados (por ejemplo, enviar un JSON donde se espera un entero).
- Formatos no estándar (fechas mal formadas, parámetros con codificación anidada, etc.).

### 🔧 Herramientas como Burp Suite son clave

Con herramientas como **Burp Proxy** y **Repeater** podés interceptar y modificar cada solicitud enviada al servidor. Por ejemplo, podés eliminar controles del lado cliente, forzar valores no permitidos o alterar el orden lógico del flujo.

Preguntas clave al observar las respuestas de la aplicación:

- ¿El servidor **impone límites** al valor ingresado?
- ¿Qué ocurre cuando el valor se sale de rango?
- ¿Se hace alguna transformación (ej. `parseInt`, `Math.abs`) o normalización silenciosa?
- ¿Se devuelve un mensaje de error, o la acción se ejecuta igual?

---

## 🗑️ Patrón común: una falla lleva a otras

Si un formulario no maneja correctamente entradas atípicas, es probable que **otras partes de la aplicación tampoco lo hagan**. Este es un patrón de diseño inseguro que puede aprovecharse para escalar privilegios, manipular precios, o acceder a funciones restringidas.

[Lab: High-level logic vulnerability](2_High-level_logic_vulnerability.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)  

---


### 3. Suponer que los usuarios siempre completan pasos del flujo

Uno de los errores más frecuentes y peligrosos en el diseño de aplicaciones es suponer que los usuarios siempre se comportarán de forma legítima y respetarán el flujo de trabajo previsto. En el mundo real, los usuarios maliciosos (o incluso usuarios legítimos curiosos) pueden y **van a** intentar interactuar con la aplicación de formas no anticipadas.

Estas suposiciones erróneas son el origen de muchas **vulnerabilidades de lógica de negocios**, ya que los desarrolladores, al no contemplar escenarios atípicos, dejan huecos en los controles y validaciones. Este tipo de fallos no siempre es técnico en esencia, sino conceptual: ocurre cuando se asume más de lo que realmente se controla.

[Lab: Inconsistent security controls](3_Inconsistent_security_controls.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)  

---

### 🔐 Trusted users won't always remain trustworthy

Una suposición **extremadamente peligrosa** en seguridad web es creer que una vez que un usuario ha superado ciertas validaciones iniciales, se puede confiar en él de forma permanente.

#### 💡 Ejemplo práctico:

Supongamos una plataforma de e-learning donde, al momento de registrarse, los usuarios deben ingresar una dirección de correo corporativa para acceder a cursos premium. Se valida correctamente durante el registro que el correo termine en `@empresa.com`, y si pasa, el usuario accede a más funcionalidades.

Sin embargo, la aplicación **nunca vuelve a validar** esa condición más adelante. ¿Qué ocurre si el usuario edita directamente su perfil y cambia el email a `@gmail.com`? ¿O si accede a funcionalidades futuras con un rol premium sin haber sido revalidado? Si no se vuelve a validar esa condición, el sistema queda abierto a abusos.

> ❗ Este tipo de fallo es común en sistemas que confían en información **almacenada** o en decisiones tomadas en momentos anteriores, sin reevaluar su validez actual.

---

### ♻️ Flujos inconsistentes y validaciones parciales

Muchos sistemas aplican validaciones estrictas durante el registro o en pasos críticos iniciales (como la compra de un producto o el alta de un usuario), pero luego **relajan** las mismas validaciones en operaciones futuras. Esto puede permitir que un atacante aproveche ese “relajamiento” para realizar acciones maliciosas, como:

- Cambiar información ya validada por el sistema sin pasar nuevamente por controles (por ejemplo, cambiar una cuenta bancaria verificada).
- Repetir procesos validados una vez, pero que deberían ser reevaluados (como transferencias de fondos, cambios de dirección de envío, acceso a recursos premium).
- Enviar peticiones manualmente sin seguir el flujo de la interfaz, usando herramientas como Burp Repeater o scripts automatizados.

---

### ✅ Buenas prácticas para evitar estas suposiciones peligrosas

- **Validar de forma consistente** todas las acciones importantes, no solo en el registro o punto de entrada.
- **Revalidar la información sensible** cada vez que se usa en una operación crítica.
- **Nunca confiar en el estado del cliente**: cualquier validación en el frontend debe repetirse (y reforzarse) del lado del servidor.
- **Documentar claramente** los supuestos que hacen los desarrolladores y revisar periódicamente si siguen siendo válidos.
- **Monitorear patrones anómalos** de comportamiento del usuario que puedan indicar intentos de abuso de la lógica de negocio.

---

🏛️ En resumen, confiar en que los usuarios actuarán según lo previsto es una receta para el desastre. Las aplicaciones deben ser diseñadas asumiendo que los atacantes intentarán violar todas las reglas posibles, y por eso la validación y los controles deben ser constantes, coherentes y del lado del servidor.



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

