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

Procedemos a realizar un `Sniper` Attack con `Burpsuite`, probando una lista de etiquetas para ver cuáles son permitidas:
![image](https://github.com/user-attachments/assets/9357528c-1987-4d5e-aec5-fda2b8ef44bf)

Vemos que la etiqueta body está permitida:
![image](https://github.com/user-attachments/assets/cd27ac53-2103-4ad0-a3cc-4e1daea2189d)

Ahora intentamos inyectar este payload:
```javascript
<body onload=print()>
```
Pero el atributo está siendo bloqueado por el `waf`:
![image](https://github.com/user-attachments/assets/6e4fbda8-c484-45b2-8b53-5c90868d0ba5)

Procedemos a realizar fuerza bruta nuevamente con `Burpsuite Intruder` para averiguar qué atributos no están siendo bloqueados, utilizamos una lista de atributos:
![image](https://github.com/user-attachments/assets/cbdca5c1-a396-4800-8383-e9625410a7d5)
Encontramos los siguientes posibles atributos:
![image](https://github.com/user-attachments/assets/3f9e4fbd-7c11-48a8-98a8-c2e672ac1d66)

### ✅ 💥 Eventos prometedores para XSS automático

| Evento            | ¿Cuándo se dispara?                              | ¿Potencial para XSS automático? | Notas |
|------------------|--------------------------------------------------|------------------------------|-------|
| `onresize`       | Cuando el tamaño del elemento cambia             | ✅ Alta                      | Muy útil con `<body>` o `iframe`, como en el lab. |
| `onscrollend`    | Cuando termina un scroll                         | ⚠️ Media                    | Necesita scroll → no es 100% automático. |
| `onsuspend`      | Cuando un recurso multimedia se suspende         | ⚠️ Media-baja               | Requiere video/audio. Poco confiable. |
| `onformdata`     | Cuando se recolectan datos de un formulario      | ❌ Baja                     | Necesita interacción. |
| `onpointercancel`| Al cancelarse una interacción del puntero        | ❌ Baja                     | Requiere acción del usuario. |
| `onratechange`   | Cuando cambia la velocidad de un video/audio     | ❌ Baja                     | Difícil de forzar sin interacción. |
| `onwebkit...`    | Son eventos específicos de navegadores WebKit    | ⚠️ Baja a media             | Muy dependientes del navegador, no garantizados. |










