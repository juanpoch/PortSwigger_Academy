# Lab: Limit overrun race conditions

This lab's purchasing flow contains a race condition that enables you to purchase items for an unintended price.

To solve the lab, successfully purchase a `Lightweight L33t Leather Jacket`.

You can log in to your account with the following credentials: `wiener:peter`.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

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

Procedemos a eliminar el cupón aplicado haciendo click en `Remove`:
![image](https://github.com/user-attachments/assets/cc83ef4d-fb6e-403e-9996-e286850debf3)

Enviamos la solicitud `POST /cart/coupon` al `Repeater` para inspeccionar mejor el proceso. Vemos que la solicitud tarda un tiempo en realizarse, puntualmente se demora 251 ms:
![image](https://github.com/user-attachments/assets/d1cee291-1727-431c-839a-66486e4728a9)

Esta es una buena noticia, porque podremos hacer múltiples peticiones en 251 ms, y posiblemente podremos realizar múltiples peticiones de cupón de descuento en esta ventana de tiempo.

Para producir este ataque, volvemos a remover el cupón de descuento mediante el botón `Remove` y luego enviamos la solicitud `POST /cart/coupon` al `Intruder`:
![image](https://github.com/user-attachments/assets/e28937f6-628b-4409-a9a2-09aeea6e2828)

Configuramos el `Intruder` para enviar 10 `Null Payloads`:
![image](https://github.com/user-attachments/assets/f26a8a7b-daac-40bd-897a-6fa58678fc84)


Realizamos el ataque:
![image](https://github.com/user-attachments/assets/0f3979bc-ce15-4e40-a11a-d51a0a0d89b9)

En este caso como tenemos Burp Suite community edition, no se puede efectuar el ataque en la ventana de tiempo, pero deberían salir varias solicitudes con `Length=100` el cual corresponde al mensaje `Coupon applied`.


Vamos a realizar un método con el `Repeater` para realizar múltiples solicitudes al mismo tiempo.


En el `Repeater` hacemos click en los 3 puntos y seleccionamos `Create tab group`:
![image](https://github.com/user-attachments/assets/d87de45b-7933-4176-a26c-f34a3ef5a881)

Luego enviamos la misma solicitud más de 30 veces, presionando `CTRL R` en el teclado. Acto seguido, enviaremos todas las solicitudes en paralelo, haciendo click en el botón desplegable del botón send y eligiendo `Send group in parallel (single-packet attack)`:
![image](https://github.com/user-attachments/assets/f350cb83-654b-495e-a2ac-be63e2391ccf)
![image](https://github.com/user-attachments/assets/b45fbea1-87a9-4efd-864f-536c4f001a72)

Realizamos el ataque y vemos que algunos aplicaron y otros no. Removemos el cupón y atacamos de nuevo:
![image](https://github.com/user-attachments/assets/a434d99b-2a74-4482-9dcf-80d90d6f41dc)














