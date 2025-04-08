Lab: Reflected XSS with event handlers and href attributes blocked


This lab contains a reflected XSS vulnerability with some whitelisted tags, but all events and anchor `href` attributes are blocked.

To solve the lab, perform a cross-site scripting attack that injects a vector that, when clicked, calls the `alert` function.

Note that you need to label your vector with the word "Click" in order to induce the simulated lab user to click your vector. For example:

```html
<a href="">Click me</a>
```
---


Como se trata de un contexto HTML entre etiquetas, sabemos que el parámetro de búsqueda refleja el payload que se le inyecte:
![image](https://github.com/user-attachments/assets/6d1bb63e-6238-4146-b8b0-6707ef8d6611)

Tembién sabemos que tenemos un waf que bloquea la mayoría de las etiquetas:
![image](https://github.com/user-attachments/assets/d34ec8c0-b27e-4ab5-8fb0-203c84c0e680)

Por lo que dice el ejercicio, el waf tiene una lista blanca de etiquetas, entre las cuales, está permitida al etiqueta `<a>`:
![image](https://github.com/user-attachments/assets/f274c733-f853-4e80-b3f3-0bb47a9f0cec)

Sin embargo si queremos inyectar la siguiente etiqueta:
```html
<a href="javascript:alert(1)">Click me</a>
```
Vemos que el atributo `href` está bloqueado:
![image](https://github.com/user-attachments/assets/9887dbca-5f68-4839-9f95-cfb9a2fc68f9)




