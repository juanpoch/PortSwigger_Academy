# Lab: DOM XSS in jQuery anchor href attribute sink using location.search source

This lab contains a DOM-based cross-site scripting vulnerability in the submit feedback page. It uses the jQuery library's `$` selector function to find an anchor element, and changes its `href` attribute using data from `location.search`.

To solve this lab, make the "back" link alert `document.cookie`.

---

Tenemos una página para visualizar comentarios:
![image](https://github.com/user-attachments/assets/c51ee4ab-fecc-4c7e-a839-55ebac682c97)


Si entramos a `submit feedback`:
![image](https://github.com/user-attachments/assets/98eafaa0-6259-411e-bed4-9b368e31ef88)

Tenemos la función de dejar un comentario.

Inspeccionamos la funcionalidad de `< Back`:
![image](https://github.com/user-attachments/assets/5e0b44b4-75ba-484a-9fe8-6079610571d1)



