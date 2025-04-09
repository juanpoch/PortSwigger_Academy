# Lab: Reflected XSS into attribute with angle brackets HTML-encoded
This lab contains a reflected cross-site scripting vulnerability in the search blog functionality where angle brackets are HTML-encoded. To solve this lab, perform a cross-site scripting attack that injects an attribute and calls the `alert` function. 

`Hint:` Just because you're able to trigger the `alert()` yourself doesn't mean that this will work on the victim. You may need to try injecting your proof-of-concept payload with a variety of different attributes before you find one that successfully executes in the victim's browser. 

---

Ingresamos un payload de prueba y vemos que es reflejado en 2 oportunidades, una de ellas es en contexto de atributo:
![image](https://github.com/user-attachments/assets/04515733-0eeb-45f0-9c3e-e9f7e0744fd0)

