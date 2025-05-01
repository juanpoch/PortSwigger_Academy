# Lab: Flawed enforcement of business rules

This lab has a logic flaw in its purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: `wiener:peter`

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)


**Técnicas aplicadas:** Business Logic Exploitation, Coupon Abuse, Fuzzing Validation Gaps  
**Herramientas:** Burp Suite (Proxy, Repeater)  
**Vulnerabilidad:** Flawed Enforcement of Business Rules



---


Iniciamos el laboratorio y nos encontramos con una clásica aplicación de shopping:
![image](https://github.com/user-attachments/assets/f3be035e-1cc6-4af5-bac4-e7a2c22f6cfe)

Iniciamos sesión con nuestras credenciales `wiener:peter`:
![image](https://github.com/user-attachments/assets/98f5a77f-22cd-44b3-b535-b6090261a594)

Nosotros tenemos $100, sabemos que el producto que tenemos que comprar, `Lightweight l33t leather jacket` es más caro. Procedemos a realizar el flujo de compra para analizarlo.

Vamos a `Home`:
![image](https://github.com/user-attachments/assets/0c7374c5-05d4-45a9-ad7d-4f6d83f2e3b1)

Efectivamente vemos que el producto está más caro, hacemos click en `View details`:
![image](https://github.com/user-attachments/assets/2b90aa38-b0ca-4b41-bbae-0d1fc9c85a8d)

Capturamos con `Burp Suite` y hacemos click en `Add to cart`:
![image](https://github.com/user-attachments/assets/aab65bfc-da83-4823-b70b-90e58eb73946)

Esta petición puede ser interesante ya que tramita los parámetros `productId=1&redir=PRODUCT&quantity=1` en el cuerpo de la solicitud.

Nos dirigimos al carrito accediendo al endpoint `/cart`:
![image](https://github.com/user-attachments/assets/151ce4f8-a147-4311-a13f-c91dcea85fdb)

Observamos que hay una nueva funcionalidad, la de ingresar un código de descuento. Nosotros tenemos el código de descuento `NEWCUST5`, lo ingresamos y analizamos la petición:
![image](https://github.com/user-attachments/assets/78a70895-d636-42b8-a0ed-3d1eef79d9d3)

![image](https://github.com/user-attachments/assets/e3263519-71da-4e1a-b6fb-fd8d8a873938)


Uno de los típicos ataques que se pueden realizar, es intentar aplicar múltiples veces el mismo código de descuento para analizar si la aplicación está validando que ya se ingresó una vez. Enviamos la petición al repeater y aplicamos el código:
![image](https://github.com/user-attachments/assets/d70cc1fc-0afd-4049-8bd3-6120eef2e881)

Vemos que nos devuelve el mensaje `Coupon already applied`, por lo que la aplicación está validando esto correctamente.

El siguiente paso sería hacer fuerza bruta sobre los códigos de descuento, para ver si efectivamente hay otros cupones disponibles que se puedan aplicar, pero seguiremos inspeccionando en búsqueda de fallas lógicas.

Volvemos a `Home` y buscamos la existencia de nuevas funcionalidades.

Observamos que hay una nueva funcionalidad `Sign up to our newsletter!`:
![image](https://github.com/user-attachments/assets/ec412e6d-70e7-4577-9958-17bf11c9afdd)

Ingresamos el mail de prueba `test@test.com` y hacemos click en `Sign up`, vemos que nos brindan el cupón `SIGNUP30`:
![image](https://github.com/user-attachments/assets/99793ffd-b088-453b-b6df-25390e2192f3)

Usando Burp Suite Repeater aplicamos el descuento en el endpoint `/cart/coupon` y observamos que el servidor nos devuelve el mensaje `Coupon applied`:
![image](https://github.com/user-attachments/assets/4560d843-82a5-44dc-9908-531caa4253c2)

Por lo que si observamos el carrito, logramos ver que tenemos efectivamente el descuento aplicado:
![image](https://github.com/user-attachments/assets/49c61389-4bf4-4cbd-82c9-07be7614be78)

Intentamos reenviar el cupón nuevamente pero con este cupón el servidor también nos devuelve el mensaje `Coupon already applied`:
![image](https://github.com/user-attachments/assets/b048e4f3-2568-4f49-98fa-841578fd06a2)

Lo siguiente a probar es si el servidor valida únicamente que el último cupón aplicado no se repita, por lo que intentaremos aplicar el cupón `NEWCUST5` nuevamente con la esperanza de que con esta falla, podramos ir alternando y aplicando los descuentos múltiples veces.

Procedemos entonces a aplicar ahora el cupón `NEWCUST5` y observamos que el servidor nos devuelve el mensaje `Coupon applied`:
![image](https://github.com/user-attachments/assets/51bfaf41-c964-4057-ad32-a832de01bfe5)

Volvemos a aplicar el código `SIGNUP30` y el servidor nos devuelve el mensaje `Coupon applied`, por lo que nuestra teoría era cierta:
![image](https://github.com/user-attachments/assets/1058fad6-8d5e-4225-82e2-7cacd5b7d387)

Accedemos al endpoint `/cart` y observamos los descuentos aplicados:
![image](https://github.com/user-attachments/assets/b6f9cfda-2916-4627-94ed-b9d6cc16ceaf)

Aplicamos los descuentos múltiples veces hasta que podamos comprar el producto:
![image](https://github.com/user-attachments/assets/7ae205c3-ca9f-4115-bd87-e7cba9ae3dbd)

Compramos el producto haciendo click en `Place order` y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/6f4afe44-72bd-4deb-a426-c01606a76008)


### ✅ Conclusión

El sistema permite aplicar múltiples códigos de descuento de forma alternada debido a una validación defectuosa. Aunque impide usar un mismo cupón más de una vez consecutiva, no bloquea el uso intercalado entre varios cupones.

Este tipo de vulnerabilidad demuestra una **implementación incorrecta de las reglas de negocio**, permitiendo a usuarios maliciosos reducir drásticamente el precio de un producto mediante abuso de cupones.

### 🛡️ Recomendaciones

- Implementar una lógica de validación que registre **cuáles cupones ya fueron aplicados**, no solo el último.
- Asociar los cupones aplicados a la sesión o al carrito, y bloquear repeticiones.
- Validar en el backend que el monto total refleje los descuentos esperados, evitando montos negativos o irrisorios.


