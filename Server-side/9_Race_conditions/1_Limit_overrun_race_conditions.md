# Lab: Limit overrun race conditions

This lab's purchasing flow contains a race condition that enables you to purchase items for an unintended price.

To solve the lab, successfully purchase a `Lightweight L33t Leather Jacket`.

You can log in to your account with the following credentials: `wiener:peter`.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

---

Una **limit overrun race condition** es una condición de carrera que permite evadir restricciones de lógica de negocio aplicando múltiples solicitudes en una ventana crítica de tiempo. Ocurre cuando una aplicación verifica una condición (como si un cupón ya fue usado), pero la acción que modifica ese estado ocurre en un paso separado. Este desfase permite a un atacante realizar múltiples operaciones simultáneamente antes de que el estado se actualice, aprovechando un tipo de vulnerabilidad conocido como **TOCTOU (Time Of Check to Time Of Use)**.

El concepto de TOCTOU se refiere a una discrepancia entre el momento en que se realiza una verificación y el momento en que se usa esa información. En aplicaciones web, este tipo de fallas pueden explotarse enviando múltiples solicitudes paralelas, generando una colisión lógica y rompiendo los límites establecidos por el sistema, como aplicar varias veces un cupón de descuento, canjear créditos repetidamente o eludir controles antifraude.

---


---

Accedemos al laboratorio y nos encontramos con una aplicación de shopping:
![image](https://github.com/user-attachments/assets/2ef7c095-d5ed-4ce1-9cb5-d0decb4eb0b0)


Nos autenticamos con nuestras credenciales `wiener:peter` y accedemos a nuestro dashboard:

![image](https://github.com/user-attachments/assets/539076dc-e5d6-4318-82b1-5d2aa197fbea)

Identificamos que el producto `Lightweight L33t Leather Jacket` tiene un precio muy por encima del dinero que poseemos:
![image](https://github.com/user-attachments/assets/745dacbf-32de-46e9-beb0-f4ce667e08b9)

Hacemos click en `View details`:
![image](https://github.com/user-attachments/assets/0d00cdde-e834-4454-9688-cebb7307777a)

Luego en `Add to cart`:
![image](https://github.com/user-attachments/assets/bdd5a98b-f4e5-4713-83f2-fca4df831dd5)


Nos dirigimos al carrito:
![image](https://github.com/user-attachments/assets/3d077ccf-358c-48b0-9fdc-f44daebcc906)


Procedemos a aplicar nuestro cupón `PROMO20` y recibimos el mensaje `Coupon applied`:
![image](https://github.com/user-attachments/assets/81e90347-96c0-438f-920c-56b7b14c1ae7)

Intentamos aplicar nuevamente nuestro cupón `PROMO20` y recibimos el mensaje `Coupon already applied`:
![image](https://github.com/user-attachments/assets/189b7347-ffba-4b0e-b287-4d5b10955d59)


Y nos redirige al endpoint `/cart?couponError=COUPON_ALREADY_APPLIED&coupon=PROMO20`:
![image](https://github.com/user-attachments/assets/1be563e1-2ebb-460e-868c-b9d8e0734d92)

Por lo que sabemos que cada vez que nos redirija a este endpoint, no estaremos siendo capaces de aplicar el cupón de descuento.

Procedemos a eliminar el cupón aplicado haciendo click en `Remove` (es necesario actualizar el endpoint `/cart`):

![image](https://github.com/user-attachments/assets/bc43f19e-66d5-46f8-96ab-9873aec435f3)

Endpoint `/cart` una vez removido el cupón:

![image](https://github.com/user-attachments/assets/cc83ef4d-fb6e-403e-9996-e286850debf3)

Enviamos la solicitud `POST /cart/coupon` al `Repeater` para inspeccionar mejor el proceso. Vemos que la solicitud tarda un tiempo en realizarse, puntualmente se demora 251 ms:
![image](https://github.com/user-attachments/assets/d1cee291-1727-431c-839a-66486e4728a9)

Esta es una buena noticia, porque podremos hacer múltiples peticiones en 251 ms, y posiblemente podremos realizar múltiples peticiones de cupón de descuento en esta ventana de tiempo.


Podríamos configurar el `Intruder` para enviar 10 `Null Payloads`:
![image](https://github.com/user-attachments/assets/f26a8a7b-daac-40bd-897a-6fa58678fc84)


Pero en este caso vamos a realizar un método con el `Repeater` para realizar múltiples solicitudes al mismo tiempo, lo cual es mucho más eficiente.


En el `Repeater` hacemos click en los 3 puntos y seleccionamos `Create tab group`:
![image](https://github.com/user-attachments/assets/e8022194-42e8-4959-8bfd-fc44e9928405)


Luego enviamos la misma solicitud más de 30 veces, presionando `CTRL R` en el teclado. Acto seguido, enviaremos todas las solicitudes en paralelo, haciendo click en el botón desplegable del botón send y eligiendo `Send group in parallel (single-packet attack)`:
![image](https://github.com/user-attachments/assets/448256cb-fa2f-47a8-9546-67d1995e50d2)


Realizamos el ataque y vemos que algunos aplicaron y otros no:
![image](https://github.com/user-attachments/assets/4884b9ac-83ea-4ae4-a6bb-0f8218014b37)

Actualizamos el endpoint `/cart` y vemos que estuvimos cerca de aplicar los descuentos necesarios para poder comprar el producto:
![image](https://github.com/user-attachments/assets/f521864f-4e92-4aff-8e55-d658a856addf)


Removemos el cupón y atacamos de nuevo, lo hacemos varias veces hasta que podemos comprar el producto:
![image](https://github.com/user-attachments/assets/69d4f444-960b-4bb4-bcb3-88bdd363ca12)

Compramos el producto y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/906cddbc-d8fb-4516-8c17-207672ce4f26)

---

## ✅ Conclusión

Este laboratorio demostró una vulnerabilidad de tipo **race condition** en el flujo de compra de una tienda online, específicamente un **limit overrun**. La lógica de aplicación del cupón `PROMO20` contenía una falla del tipo **TOCTOU (Time-of-Check to Time-of-Use)**, permitiendo aplicar el mismo descuento más de una vez si las solicitudes se enviaban en paralelo durante la "ventana de carrera". Mediante el uso de la funcionalidad **Send group in parallel (single-packet attack)** de Burp Repeater, logramos ejecutar múltiples solicitudes dentro de ese micro-segmento de tiempo, aplicando el descuento varias veces y logrando comprar el producto por debajo de su precio real.

---

## 🛡 Recomendaciones

- **Sincronización transaccional**: Implementar operaciones atómicas o bloqueos a nivel de base de datos para evitar condiciones de carrera durante la verificación y aplicación de descuentos.
- **Validación posterior al procesamiento**: Asegurarse de verificar nuevamente si el cupón ya fue usado justo antes de confirmar la transacción, no solo al inicio del proceso.
- **Limitar acciones simultáneas por sesión**: Restringir la cantidad de operaciones que pueden realizarse desde una misma cuenta/session/IP en un corto período de tiempo.
- **Auditoría de condiciones de carrera**: Analizar todos los procesos multi-paso que modifiquen estados sensibles (como saldos, descuentos, o canjes) para identificar posibles TOCTOU.

---

## 📚 Lecciones aprendidas

- Las condiciones de carrera no requieren acceso avanzado al sistema: pueden explotarse desde la lógica de negocio, simplemente manipulando el tiempo y la concurrencia.
- Herramientas como **Burp Suite Repeater (2023.9+)** ofrecen capacidades muy potentes para enviar solicitudes simultáneas, como el **single-packet attack**, clave para este tipo de explotación.
- Es crucial entender la diferencia entre "check" y "use" en flujos transaccionales. Cuando están desacoplados, existe la posibilidad de explotar esa brecha temporal.
- La explotación exitosa no siempre requiere vulnerabilidades técnicas complejas: los errores lógicos o de diseño pueden tener impactos igual o más severos.



