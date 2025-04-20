# Lab: DOM XSS in document.write sink using source location.search inside a select element

This lab contains a DOM-based cross-site scripting vulnerability in the stock checker functionality. It uses the JavaScript `document.write` function, which writes data out to the page. The `document.write` function is called with data from `location.search` which you can control using the website URL. The data is enclosed within a select element.

To solve this lab, perform a cross-site scripting attack that breaks out of the select element and calls the `alert` function.  

![Practitioner](https://img.shields.io/badge/level-Practitioner-blue)


---

Tenemos una aplicación web que nos permite ver distintos productos de un shop:
![image](https://github.com/user-attachments/assets/e0f1fb0d-6d0b-4f4d-99e3-4d1ea9b189f7)

En este caso buscamos etiquetas `<script>` en el código sin éxito:
![image](https://github.com/user-attachments/assets/d942cdcc-af38-4cbe-91a6-3c2d52bd5147)

Hacemos click en la opción `View details`:
![image](https://github.com/user-attachments/assets/19a2816f-93c3-4fcc-9d05-9de39de29fa3)

Intentamos encontrar etiquetas `<script>` nuevamente:
![image](https://github.com/user-attachments/assets/e6b1f4b8-6169-435a-9049-d45d1376e32a)

Tenemos el siguiente fragmento de código:
```js
<script>
    var stores = ["London","Paris","Milan"];
    var store = (new URLSearchParams(window.location.search)).get('storeId');
    document.write('<select name="storeId">');
    if(store) {
        document.write('<option selected>'+store+'</option>');
    }
    for(var i=0;i<stores.length;i++) {
        if(stores[i] === store) {
            continue;
        }
        document.write('<option>'+stores[i]+'</option>');
    }
    document.write('</select>');
</script>
```




