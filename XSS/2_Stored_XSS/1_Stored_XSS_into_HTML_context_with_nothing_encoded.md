# Lab: Stored XSS into HTML context with nothing encoded  

This lab contains a stored cross-site scripting vulnerability in the comment functionality.  

To solve this lab, submit a comment that calls the alert function when the blog post is viewed.  

---  

Ingresamos a un website donde se visualizan posteos de diferentes usuarios:
![image](https://github.com/user-attachments/assets/3b973225-7d84-4e4d-a9ef-2fe7b62512f1)
Cuando accedemos a un post, podemos visualizar los comentarios de los usuarios y comentar nosotros también:
![image](https://github.com/user-attachments/assets/9d5b491c-0ba8-46bc-b558-af61ae8c4368)

Realizamos un comentario de prueba:
![image](https://github.com/user-attachments/assets/d3c6122a-133d-43da-bf4f-c81869d0dd57)

Vemos que se almacena el payload "test" en el comentario, probamos con un payload malicioso:

![image](https://github.com/user-attachments/assets/f5abf470-36f3-492d-b426-a07c1fe7765d)

Posteamos y accedemos a visualizar el comentario a ver si se ejecuta (click en "back to blog"):
![image](https://github.com/user-attachments/assets/2a03f9c5-d48a-4f10-accd-d86da0fea847)
![image](https://github.com/user-attachments/assets/5d8b5366-e565-4033-8c50-6f6b0c951f13)






