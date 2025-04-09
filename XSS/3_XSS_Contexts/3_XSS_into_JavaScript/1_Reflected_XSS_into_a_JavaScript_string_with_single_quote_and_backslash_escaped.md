# Lab: Reflected XSS into a JavaScript string with single quote and backslash escaped

This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality. The reflection occurs inside a JavaScript string with single quotes and backslashes escaped.

To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

---

Realizamos una consulta de prueba e identificamos el contexto de la reflexión, en este caso hay reflexión tanto entre etiquetas `html` como en la función de seguimiento de consultas de búsqueda:
![image](https://github.com/user-attachments/assets/4fdb50f8-775a-408f-b49a-589c7d5b71c8)

También vemos que las comillas simples `'` son escapadas con una barra `\`:
![image](https://github.com/user-attachments/assets/18eb6005-48eb-48b6-a0c2-98ac0f3feb7d)


Ejecutamos el siguiente payload:
```html
</script><img src=1 onerror=alert(document.domain)>
```
Y resolvemos el lab:
![image](https://github.com/user-attachments/assets/9f307cc0-f750-4788-a5f1-726fc7ff0057)
![image](https://github.com/user-attachments/assets/01370356-a38c-4026-b083-848ed3c8d65f)



