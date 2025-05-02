# Race Conditions 

## ¿Qué es una race condition?

Una **race condition** es una vulnerabilidad que ocurre cuando una aplicación web procesa múltiples solicitudes concurrentes sin mecanismos adecuados de sincronización o bloqueo. Esto permite que dos o más hilos de ejecución accedan a recursos compartidos de forma simultánea, generando comportamientos inesperados.

Estas vulnerabilidades están íntimamente relacionadas con los **business logic flaws** y su explotación se basa en generar colisiones entre operaciones que no deberían solaparse en el tiempo.

La **ventana de carrera (race window)** es el pequeño periodo de tiempo entre dos operaciones dependientes que puede ser explotado si se actúa rápidamente antes de que el sistema actualice su estado interno.

---

## Ejemplo de una race condition: Código de descuento reutilizable

### Lógica esperada (una sola solicitud):

1. El usuario envía un código de descuento.
2. El servidor verifica: `code_already_used == false`.
3. Aplica el descuento.
4. Actualiza el código como usado: `code_already_used = true`.

![image](https://github.com/user-attachments/assets/4b8877b7-b562-4031-a8c7-3ab32b2c8e6d)


### Lógica vulnerable (dos solicitudes simultáneas):

Si dos solicitudes se envían casi al mismo tiempo:

* Ambas verifican que `code_already_used == false`.
* Ambas aplican el descuento.
* Ambas marcan el código como usado.

Esto ocurre porque ambas solicitudes acceden a una **sub-state** transitoria antes de que el sistema se actualice correctamente.

![image](https://github.com/user-attachments/assets/eed33616-9620-45e2-8205-96da2e35d1dd)


---

## Tipos comunes de ataques por race condition

* Reutilizar un código de descuento.
* Canjear varias veces una gift card.
* Realizar retiros o transferencias que exceden el saldo.
* Reutilizar una solución de CAPTCHA.
* Eludir un mecanismo anti-fuerza bruta o de rate limiting.

Estos ataques suelen ser una forma de **TOCTOU** (Time-of-Check to Time-of-Use).

---

## Detección y explotación con Burp Suite

### Paso 1: Identificar el endpoint vulnerable

Buscar funcionalidades de:

* Uso único (e.g., descuentos).
* Acciones limitadas por tiempo o cantidad.

### Paso 2: Lanzar solicitudes en paralelo

El principal desafío es sincronizar las solicitudes para que al menos dos ventanas de carrera coincidan, lo que provocaría una colisión. Esta ventana suele ser de tan solo milisegundos, e incluso puede ser más corta.

Incluso si envía todas las solicitudes exactamente al mismo tiempo, en la práctica hay varios factores externos incontrolables e impredecibles que afectan cuándo el servidor procesa cada solicitud y en qué orden.

![image](https://github.com/user-attachments/assets/fea24e3e-b42a-45d4-bd9a-342f03099501)


### Paso 3: Enviar 20-30 solicitudes para maximizar colisiones

Burp Repeater (desde la versión 2023.9) permite:

* Para HTTP/1: **Last-byte synchronization**.
* Para HTTP/2: **Single-packet attack** (investigación de PortSwigger, Black Hat USA 2023).

Este último reduce a cero el impacto del network jitter, completando todas las solicitudes dentro del mismo paquete TCP.

![image](https://github.com/user-attachments/assets/9dff6522-9461-4f81-826c-109c07a695a8)


### Herramientas recomendadas

* Burp Suite Repeater (modo concurrente).
* Intruder (en modo cluster bomb o sniper para pruebas simples).
* curl + bash loop (como alternativa).

---

## Referencias

* [Smashing the state machine: The true potential of web race conditions (PortSwigger Research)](https://portswigger.net/research/smashing-the-state-machine)
* [Burp Suite Docs - Sending requests in parallel](https://portswigger.net/burp/documentation/repeater/parallel)

---

## Resumen

Las race conditions representan vulnerabilidades críticas cuando se explotan en lógicas sensibles como pagos, transferencias, descuentos o autenticación. Con una buena comprensión de su comportamiento interno, es posible encontrar y explotar estas fallas en ambientes reales o de laboratorio.

> 💡 **Consejo**: Identificá flujos que impliquen validación previa y posterior actualización de estado. Ahí es donde suele estar la ventana de carrera.


[Lab: Limit overrun race conditions](1_Limit_overrun_race_conditions.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 
