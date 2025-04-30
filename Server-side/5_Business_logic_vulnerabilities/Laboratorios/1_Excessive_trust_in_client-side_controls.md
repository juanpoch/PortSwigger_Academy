# Lab: Excessive trust in client-side controls

This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: `wiener:peter`

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)  

---

Iniciamos el laboratorio y tenemos una aplicación de compras:
![image](https://github.com/user-attachments/assets/828fdaec-b119-4dee-ab5c-04597b45c593)

Utilizamos el botón `My account` para acceder al panel de login e iniciar sesión con nuestras credenciales:
![image](https://github.com/user-attachments/assets/a952d9d9-b5eb-4804-a94d-1a085d559171)


Vemos que tenemos apenas $100 dólares para gastar, pero tenemos que comprar el producto `Lightweight l33t leather jacket` que sale mucho más caro:
![image](https://github.com/user-attachments/assets/49c29f8c-64aa-4d9c-94c9-d96155518e6f)

Buscamos un producto que sea barato para inspeccionar el workflow, vemos que hay un producto a $10.93:
![image](https://github.com/user-attachments/assets/38bfad6a-9aa4-4581-b014-4fcf33831174)


Hacemos click en `View details`:
![image](https://github.com/user-attachments/assets/e14eb409-8085-447d-a89b-154859078f11)

Hacemos click en `Add to cart`:  

![image](https://github.com/user-attachments/assets/903c81d4-8eeb-4e18-ac66-8d49ef238fab)

- `price=1093` está siendo enviado por el cliente, lo que indica que el precio del producto es controlable por el usuario.

- Esto sugiere que el sistema confía en el valor del parámetro `price` recibido desde el navegador, en lugar de calcular el precio en el backend.

- Este tipo de lógica puede ser explotada fácilmente para comprar productos a un precio menor o incluso negativo.

Luego ingresamos al carrito:
![image](https://github.com/user-attachments/assets/7ecbac3c-ea65-47e1-aaf3-28fdeac2b5db)



Llegamos a la siguiente página:
![image](https://github.com/user-attachments/assets/b77d9e82-47c7-4f9c-9b05-ca74464a8581)

Hacemos click en `Place order`:
![image](https://github.com/user-attachments/assets/180d2af0-9696-4c3f-aabb-ea33065d4535)

Petición en Burp Suite:
![image](https://github.com/user-attachments/assets/31df5e1a-595f-4849-bcf0-eee757005322)

Enviamos la petición `/cart` al Repeater e intentamos cambiar el parámetro `price` enviado en el cuerpo de la solicitud, vemos que tenemos éxito:
![image](https://github.com/user-attachments/assets/f847472f-5903-452e-8eba-7a9c00b05a8e)

Si vemos nuestro navegador y vamos al carrito, vemos que está nuestra compra activada:
![image](https://github.com/user-attachments/assets/140ad046-d000-41df-8479-181359bfb10b)

Hacemos click en `Place order` para ver si podemos realmente comprar el producto. Logramos comprarlo:
![image](https://github.com/user-attachments/assets/dae3b5c6-129c-46fd-979a-0f1adfd129c1)

Por lo que vamos a proceder a comprar el producto que necesitabamos, que se llama `Lightweight l33t leather jacket`, para el cual necesitamos saber el id, por lo que accedemos al mismo para ver el id en la url:
![image](https://github.com/user-attachments/assets/605d31b1-6964-43b4-86a9-212c09bf15e3)

Sabemos que es el `productId=1`. Volvemos a modificar la petición de `cart` para esta vez llevar al carrito el `productId=1` a un precio accesible:
![image](https://github.com/user-attachments/assets/14fef8f1-9ed1-4c8c-b432-9c0d78f558e1)

Accedemos al carrito y vemos que tenemos la orden de compra:
![image](https://github.com/user-attachments/assets/e1ca7e15-a636-4894-8632-9c6078033a5a)

Hacemos click en `Place order` y compramos el producto para resolver el laboratorio:
![image](https://github.com/user-attachments/assets/f0991872-f9eb-428c-becf-d285ee337514)










