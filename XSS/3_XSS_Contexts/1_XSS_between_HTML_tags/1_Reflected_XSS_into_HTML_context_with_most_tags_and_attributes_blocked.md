Lab: Reflected XSS into HTML context with most tags and attributes blocked
This lab contains a reflected XSS vulnerability in the search functionality but uses a web application firewall (WAF) to protect against common XSS vectors.

To solve the lab, perform a cross-site scripting attack that bypasses the WAF and calls the print() function.  

---

Ingresamos a un portal web que nos permite realizar comentarios, realizamos un comentario de prueba:
![image](https://github.com/user-attachments/assets/ac147410-c0de-47ff-ac45-023ef6241204)

Vemos que el payload aparece reflejado en el contexto de HTML entre etiquetas:
![image](https://github.com/user-attachments/assets/eb548011-573b-4a26-b110-5d813ccaf73d)

Ya tenemos localizado el contexto, procedemos a inyectar payloads candidatos.
Al encontrarnos en un contexto HTML entre etiquetas, la metodología consiste en intentar inyectar etiquetas para ejecutar `JS`, procedemos con uno de los payloads más comunes para este caso:
```javascript
<script>alert(document.domain)</script>
```
![image](https://github.com/user-attachments/assets/f8dd0edd-8892-4387-979c-3c7badbd0759)
Vemos que un `waf` bloquea la etiqueta:
![image](https://github.com/user-attachments/assets/42b8ecc7-71ae-4d15-bf1d-1c78f0ab5ffe)
Probamos el siguiente payload el cual también está bloqueado:
```javascript
<img src=1 onerror=alert(1)>
```


