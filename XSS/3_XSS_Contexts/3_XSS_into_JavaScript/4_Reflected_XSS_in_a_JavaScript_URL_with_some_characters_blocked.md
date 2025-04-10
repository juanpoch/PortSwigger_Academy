# Lab: Reflected XSS in a JavaScript URL with some characters blocked

This lab reflects your input in a JavaScript URL, but all is not as it seems. This initially seems like a trivial challenge; however, the application is blocking some characters in an attempt to prevent XSS attacks.

To solve the lab, perform a cross-site scripting attack that calls the `alert` function with the string `1337` contained somewhere in the `alert` message.

![Expert](https://img.shields.io/badge/Level-Expert-800080?style=for-the-badge&logo=flask)

---

Nos encontramos con una sección de comentarios, observamos el parametro `postId` en el `DOM`:
![image](https://github.com/user-attachments/assets/8702a9dd-f1d1-415f-b1c6-ec03faabfd15)






