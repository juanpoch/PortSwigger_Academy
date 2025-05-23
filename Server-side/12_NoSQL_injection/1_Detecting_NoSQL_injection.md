# Lab: Detecting NoSQL injection

The product category filter for this lab is powered by a MongoDB NoSQL database. It is vulnerable to NoSQL injection.

To solve the lab, perform a NoSQL injection attack that causes the application to display unreleased products.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y nos encontramos con una aplicación de compras online:
![image](https://github.com/user-attachments/assets/1abde02c-5547-463c-8f33-6c7c22fdde9c)

Como sabemos que este laboratorio contiene un filtro de categoría vulnerable a NoSQL injection, filtramos por categoría, por ejemplo "Accessories" para analizar la petición:
![image](https://github.com/user-attachments/assets/65eb83ae-8800-4771-bb96-89f8cd8c8d6b)

Este endpoint está construyendo internamente una consulta a la base de datos NoSQL utilizando el parámetro `category`. Algo como:
```javascript
db.products.find({ category: "Accessories" })
```

Enviamos al repeater para analizar:
![image](https://github.com/user-attachments/assets/64463e85-2c66-43cb-8485-02b19e7cc798)

Como el objetivo del laboratorio es detectar una inyección NoSQL, lo siguiente sería intentar romper la sintaxis o inyectar operadores para observar cambios en la respuesta o detectar errores.

Nosotros sabemos que los principales caracteres que pueden romper una cadena de consulta son los siguientes:
```php
"
'
`
{
}
$
;
```
Por lo que iremos intentando uno por uno hasta localizar si alguno genera un error.
Probamos con el primero `"`:
![image](https://github.com/user-attachments/assets/ad6bd9a1-7a63-44dc-aae9-96c749bfced9)

Probamos con el siguiente, `'` y vemos que genera un error:
![image](https://github.com/user-attachments/assets/cbc3dada-4e72-454d-9c17-e91f7d7f96cf)

Esta respuesta con error `JSInterpreterFailure` y mensaje `SyntaxError: unterminated string literal` confirma de forma clara que hay una inyección NoSQL basada en sintaxis. El error ocurre porque se pudo romper la cadena de texto utilizada en la consulta de MongoDB.

El parámetro `category=Accessories'` rompió la sintaxis del query en el backend. Esto sugiere que el servidor está interpolando la entrada de forma insegura en una cadena tipo:
```javascript
this.category == 'Accessories''
```

Si intentamos inyectar el payload `category=Accessories'+'` url encodeado, vemos que no generamos un error de sintaxis:
![image](https://github.com/user-attachments/assets/a93e078a-a0c5-4a2f-9b9e-4203eeca158b)

es el momento ideal para probar una condición booleana controlada por nosotros.

Supongamos que tenemos una condición similar a la siguiente:
```javascript
if(this.category == "Accessories" && this.limit == 3){
//... do something
}
```
Siguiendo esta idea, intentaríamos inyectar condiciones booleanas de modo tal que podamos remover la segunda sentencia `&& this.limit == 3`.

Tenemos distintas opciones para este ataque:
```javascript
' && 1 == 1
' && '1' == '1  --> 'Accessories' && ...
' || 1 == 1
' || '1' == '1
' || 1 ||
' || 1 || '
```

Procedemos a probar uno por uno. Los payloads se inyectan url encodeados.

Primer inyección `' && 1 == 1` produce un error de sintaxis:
![image](https://github.com/user-attachments/assets/175f663d-ec0d-4157-bf6f-67ccfbc4b47b)
Segunda inyección `' && '1' == '1`, si bien no produjo un error de sintaxis, no está trayendo todos los productos (es posible que funcione bien con `||`):
![image](https://github.com/user-attachments/assets/5fe96202-3e0d-4612-a495-b92592e645d9)
Tercera inyección `' || 1 == 1` produce un error de sintaxis:
![image](https://github.com/user-attachments/assets/2a567a55-3e1e-466b-8971-48f51d133809)
Cuarta inyección `' || '1' == '1` vemos que trajo todos los productos como suponíamos:
![image](https://github.com/user-attachments/assets/6ca1c46a-d5dc-40f3-92f5-abfba0aa26b0)

Probamos las otras 2:
Quinta inyección `' || 1 ||` lanza un error de sintaxis:
![image](https://github.com/user-attachments/assets/5ff5d576-f285-484e-98bc-af80ccda8dad)
Sexta inyección `' || 1 || '` también funcionó:
![image](https://github.com/user-attachments/assets/33c80aa6-f5d5-4965-b74a-6cdacb652765)


Resolvimos el laboratorio:
![image](https://github.com/user-attachments/assets/e9d8298c-1cc2-482e-b1f3-0f2f3bddc317)

---

## ✅ Laboatorio resuelto

El payload `' || '1' == '1` permitió modificar la lógica interna de la consulta, haciendo que el filtro por categoría devuelva todos los productos, incluyendo los **"unreleased"**, como pedía el enunciado.

---

## 🔹 Conclusiones

Este laboratorio demuestra claramente cómo una inyección NoSQL puede:

- Romper la lógica de filtrado (inyección de operadores booleanos).
- Revelar productos ocultos o restringidos.
- Generar errores que exponen información sensible del backend (tracebacks).

---

## 🧰 Recomendaciones

- Nunca concatenar directamente entradas del usuario en consultas dinámicas.
- Usar ORM o query builders que escapen operadores (`$ne`, `$where`, etc.).
- Validar y sanear todas las entradas antes de pasarlas al motor de base de datos.
- Deshabilitar operadores peligrosos como `$where` en MongoDB si no son necesarios.

---

## 📃 Lecciones aprendidas

- La inyección NoSQL no se limita a operadores `$ne` o `$gt`, también puede utilizar **JavaScript inline**.
- Las respuestas error pueden ser un canal de aprendizaje para el atacante.
- Los ataques booleanos siguen siendo una técnica eficaz para inferir vulnerabilidades.

---




