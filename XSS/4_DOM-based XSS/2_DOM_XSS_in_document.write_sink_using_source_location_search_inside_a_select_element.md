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
```html
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

### 🔍 Línea por línea

```javascript
var stores = ["London","Paris","Milan"];
```

Define un arreglo con tres valores válidos: `"London"`, `"Paris"` y `"Milan"`.  
Estos son los valores legítimos que el menú desplegable debe mostrar.

---

```javascript
var store = (new URLSearchParams(window.location.search)).get('storeId');
```

Obtiene el valor del parámetro `storeId` de la URL.  
Ejemplo: si la URL es `...?storeId=Berlin`, entonces `store = "Berlin"`.

---

```javascript
document.write('<select name="storeId">');
```

Empieza a escribir en el documento un `<select>` HTML (menú desplegable).

---

```javascript
if(store) {
    document.write('<option selected>'+store+'</option>');
}
```

Si `store` existe (o sea, fue pasado por la URL), lo agrega como opción seleccionada.  
❗️ **Aquí hay un riesgo de XSS**, porque el valor viene directamente de la URL sin sanitizar y se inserta en el DOM con `document.write`.

---

```javascript
for(var i = 0; i < stores.length; i++) {
    if(stores[i] === store) {
        continue;
    }
    document.write('<option>' + stores[i] + '</option>');
}
```

Recorre el arreglo `stores`.  
Si el valor actual es igual al parámetro `store`, lo salta (porque ya se insertó como `selected`).  
Si no, lo agrega como una opción al `<select>`.

---

```javascript
document.write('</select>');
```

Cierra la etiqueta `<select>`.%  

---


Comprobamos el flujo ingresando un valor arbitrario al parámetro `storeId`:

![image](https://github.com/user-attachments/assets/32f3bfac-a83a-4e56-9cb2-ab6c90cdd18e)

Tal como se observa, el valor del parámetro `storeId` es obtenido desde la cadena de consulta mediante:
```js
var store = (new URLSearchParams(window.location.search)).get('storeId');
```
Luego, ese valor es insertado directamente en el DOM como una opción del elemento `<select>`, utilizando el sink vulnerable `document.write`:
```js
document.write('<option selected>' + store + '</option>');
```

## 💥 Manipulación del DOM mediante inyección en `storeId`

Aquí la idea es inyectar un valor en el parámetro `storeId` que permita cerrar anticipadamente la etiqueta `<option>`, rompiendo así la estructura HTML del menú desplegable.

Para lograrlo, utilizamos el siguiente payload como valor de `storeId`:

`abc123xy</option></select>`

Esto se refleja directamente en el DOM:

![image](https://github.com/user-attachments/assets/1de3c398-4609-4cfd-8c0f-d2bd41a8be0c)

Como se puede ver, el payload **cierra tanto la opción como el `<select>`** manualmente, lo cual rompe la estructura original de la página.

🔍 Este es un paso fundamental en un ataque de tipo **DOM-based XSS**, ya que abre la posibilidad de inyectar contenido HTML o JavaScript luego de cerrar correctamente las etiquetas existentes.








