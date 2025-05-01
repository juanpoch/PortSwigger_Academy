# Lab: Information disclosure in error messages

This lab's verbose error messages reveal that it is using a vulnerable version of a third-party framework. To solve the lab, obtain and submit the version number of this framework.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)  

---


Iniciamos el laboratorio y tenemos una aplicación de shopping:
![image](https://github.com/user-attachments/assets/a1f7c447-6dc6-48b4-8b44-8a358f4dfc0f)

Hacemos click en `View details` en un producto:
![image](https://github.com/user-attachments/assets/5f9f0022-0d86-4760-b311-a9b9ec5ffc3b)


No hay más funcionalidad que esta, el único parámetro que encontramos es `productId=1`, por lo que procedemos a cambiar los valores del parámetro usando el `Repeater` y vemos que cambian los productos:
![image](https://github.com/user-attachments/assets/26e847c1-0938-484c-979c-69a90e6cafc8)

Ingresamos un número muy grande y recibimos el mensaje `not found`:
![image](https://github.com/user-attachments/assets/30c289ea-5b5f-4c3f-8981-16403f0f482f)

Procedemos a ingresarle una cadena arbitraria al parámetro `productId` para analizar cómo reacciona y vemos un mensaje `500 Interna Server Error`:
![image](https://github.com/user-attachments/assets/3f144f13-b941-4ff8-9ec7-3ce292368eeb)

Si hacemos scroll down sobre la respuesta, vemos que nos revela la versión de Apache `Apache Struts 2 2.3.31`:
![image](https://github.com/user-attachments/assets/00848add-9305-4266-93a9-cb20716200b4)

Por lo que hacemos click en `submit solution` y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/71fbee61-d4fa-486c-9f8a-f8ce58d52a9b)

![image](https://github.com/user-attachments/assets/71a2297b-33a8-4164-a49e-3904ad8dbe6b)









