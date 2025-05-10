# Lab: Stored XSS into HTML context with nothing encoded  

This lab contains a stored cross-site scripting vulnerability in the comment functionality.  

To solve this lab, submit a comment that calls the alert function when the blog post is viewed.  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---  

Accedemos al laboratorio y nos encontramos con un blog público, el cual tiene muchos comentarios de distintos usuarios:
![image](https://github.com/user-attachments/assets/897b6f67-6c9b-43ff-9f3c-90a4fe7f5849)

Accedemos a un comentario de otro usuario utilizando el botón `View post`:
![image](https://github.com/user-attachments/assets/6c1b6c3a-8442-4cec-b84d-bb85a4b5261f)

A su vez notamos que nosotros también podemos comentar:
![image](https://github.com/user-attachments/assets/5e783760-1038-40ca-9afd-88325e384182)



Realizamos un comentario de prueba:
![image](https://github.com/user-attachments/assets/9e471e7f-2ba1-4213-adf5-fac2f670fe55)





Vemos que nuestra inyección en el campo comentario se almacena entre etiquetas `<p>`:
![image](https://github.com/user-attachments/assets/7d49f56a-a55e-4a69-95e9-656ac7fe34bc)

![image](https://github.com/user-attachments/assets/7df45320-dd18-4f24-bf62-1899fd1ba4df)


Probamos con un payload malicioso:

![image](https://github.com/user-attachments/assets/f5abf470-36f3-492d-b426-a07c1fe7765d)

Posteamos y accedemos a visualizar el comentario a ver si se ejecuta (click en "back to blog"):
![image](https://github.com/user-attachments/assets/2a03f9c5-d48a-4f10-accd-d86da0fea847)
![image](https://github.com/user-attachments/assets/5d8b5366-e565-4033-8c50-6f6b0c951f13)





