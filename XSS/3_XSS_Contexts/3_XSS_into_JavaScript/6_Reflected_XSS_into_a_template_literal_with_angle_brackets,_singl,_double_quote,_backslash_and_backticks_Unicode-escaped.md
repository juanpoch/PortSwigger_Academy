# Lab: Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped

This lab contains a reflected cross-site scripting vulnerability in the search blog functionality. The reflection occurs inside a template string with angle brackets, single, and double quotes HTML encoded, and backticks escaped. To solve this lab, perform a cross-site scripting attack that calls the `alert` function inside the template string.

![Practitioner](https://img.shields.io/badge/level-Practitioner-blue)

---

El sitio web es un blog que permite realizar búsquedas, procedemos a realizar una búsqueda de prueba para analizar el contexto de la reflexión:

![image](https://github.com/user-attachments/assets/126d5c60-3856-44a9-8e8f-0e2f7f108d12)

Vemos dos reflexiones, una entre etiquetas `<h1>` y la otra entre etiquetas `<script>`

La segunda es interesante porque la reflexión se encuentra entre `template literal`.

### 🧠 Template literals

Son una forma de escribir strings multilínea o interpolados en JavaScript, usando backticks (\`) en lugar de comillas `'` o `"`. Permiten insertar variables o expresiones directamente dentro del string, con la sintaxis `${...}`.

Ejemplo báscio:
```js
let nombre = "Carlos";
console.log(`Hola, ${nombre}!`);  // Output: Hola, Carlos!
```
Acá, `${nombre}` se reemplaza dinámicamente por su valor (interpolación).
También se puede usar para múltiples líneas:
```js
let mensaje = `
Hola!
Este es un mensaje
multilínea.
`;
```
Cuando el código del servidor o frontend inserta datos del usuario dentro de una template literal sin sanitizar, puede abrir la puerta a ejecución de código malicioso.

---

En el laboratorio, la reflexión se da en el siguiene contexto:
```js
<script>
var message = `0 search results for 'abc123xy'`;
...
</script>
```
En este caso, podemos insertar el siguiente payload: `${alert(1)}`

### 💥 Interpolación en Template Literals

Cuando usamos un payload como `${alert(1)}`, estamos aprovechando la capacidad de las *template literals* para ejecutar **expresiones dinámicas** dentro de `${...}`.

Aunque a simple vista parezca que solo se pueden interpolar variables, JavaScript permite evaluar cualquier **expresión válida**, como una llamada a función (`alert(1)`), una operación matemática (`1 + 2`), o incluso un condicional (`true ? 'sí' : 'no'`).

Esto hace posible ejecutar código arbitrario si el contenido del input del usuario es insertado sin sanitización dentro de una *template literal*.

En este caso, el navegador interpreta `${alert(1)}` como una expresión, la evalúa, y ejecuta `alert(1)`, lo que desencadena un **XSS reflejado**.


Inyectamos el payload y resolvemos el lab:
![image](https://github.com/user-attachments/assets/4692e526-0415-4da7-a316-37948c6df604)

Vemos que la inyección se insertó correctamente en la `template literal`:
![image](https://github.com/user-attachments/assets/08c8726c-9057-4266-9499-992cec51a466)


![image](https://github.com/user-attachments/assets/5af5faa7-7b5e-4191-a71b-2b5b7fb89434)




