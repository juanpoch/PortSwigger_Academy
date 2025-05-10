# Lab: Stored XSS into anchor href attribute with double quotes HTML-encoded
This lab contains a stored cross-site scripting vulnerability in the comment functionality. To solve this lab, submit a comment that calls the `alert` function when the comment author name is clicked. 

---

Insertamos un comentario de prueba para ver el comportamiento:
![image](https://github.com/user-attachments/assets/53c7ba6c-153b-4d61-aa81-d55925644073)

Vemos que la `url` se refleja en el atributo `href`, por lo tanto inyectamos el siguiente payload:
```html
javascript:alert(document.domain)
```
![image](https://github.com/user-attachments/assets/59767406-798c-46f4-abac-23aceecb512b)
Resolvemos el lab al hacer clic en nuestro nombre de usuario:
![image](https://github.com/user-attachments/assets/43f9b6c3-09bd-41d2-8aab-ade31570b577)



