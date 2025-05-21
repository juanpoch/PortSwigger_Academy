# Lab: JWT authentication bypass via flawed signature verification

This lab uses a JWT-based mechanism for handling sessions. The server is insecurely configured to accept unsigned JWTs.

To solve the lab, modify your session token to gain access to the admin panel at `/admin`, then delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y nos encontramos con un blog público:
![image](https://github.com/user-attachments/assets/d3c853a1-b5ea-4586-8a88-033ce11eab63)

Accedemos al panel de autenticación a través de `My account` y nos autenticamos con nuestras credenciales `wiener:peter`:

![image](https://github.com/user-attachments/assets/be69a900-cda7-4b68-a79c-ae69473d8fa4)

Notamos que nos autenticamos correctamente y el servidor nos devuelve un JWT, luego nos redirige al panel `/my-account?id=wiener`:
![image](https://github.com/user-attachments/assets/1165a975-01e2-436d-a270-9a2027c700ff)

Enviamos esa solicitud al repeater e intentamos acceder al panel `/admin`:
![image](https://github.com/user-attachments/assets/ef34fdac-bb9a-4eae-abb5-007be258a4d8)

Procedemos a intentar suplantar el campo `"sub":"wiener"` por `"sub":"administrator"` sin enviar una firma válida:
![image](https://github.com/user-attachments/assets/2a12560f-559d-40bc-a75f-24893d184479)

Notamos que no está funcionando el mismo ataque que realizamos en el laboratorio anterior.

Sabemos que el servidor está configurado de forma insegura para aceptar JWTs sin firmar, por lo que procedemos a intentar la técnica del algoritmo `none`. Utilizaremos el siguiente Header:
```json
{
    "kid": "12748a98-0107-4687-9e31-4df81ed9b4ee",
    "alg": "none"
}
```

El campo alg del header de un JWT indica qué algoritmo debe usar el servidor para verificar la firma del token. Si se permite el valor none, se está indicando literalmente que el token no está firmado y que no requiere validación criptográfica.

📌 Este tipo de vulnerabilidad es grave porque le permite al atacante suprimir completamente el uso de firma digital. Al establecer `alg: none`, el servidor interpreta que no debe verificar la integridad del token, lo que permite modificar libremente el payload y autenticarse como cualquier usuario.


El siguiente paso es generar un token con solo dos partes:
`base64url(header).base64url(payload).`.

Si el servidor acepta este token como válido, entonces podremos autenticarnos como cualquier usuario sin conocer ninguna clave secreta.

Antes de enviar la solicitud debemos firmarla con el algoritmo `none`. Para eso hacer clic en `Attack` > `"none" Signing Algorithm`, luego elegir el valor del algoritmo (en este caso `none`) y hacer clic en `OK`:
![image](https://github.com/user-attachments/assets/98ad6ba5-893c-47b1-8f22-dec772dc1619)

Enviamos la solicitud:
![image](https://github.com/user-attachments/assets/c5595203-df2d-433c-a10b-66c43625d224)

Observamos que tenemos acceso al panel administrativo con la funcionalidad de eliminar usuarios. 

Nos dirigimos al endpoint `/admin/delete?username=carlos` para eliminar al usuario `carlos` y resolver el laboratorio:
![image](https://github.com/user-attachments/assets/96325918-ab04-4097-a5da-376320321eb6)

![image](https://github.com/user-attachments/assets/68035729-f2dd-4861-99af-49c09a487c56)

![image](https://github.com/user-attachments/assets/fb46fb9e-94f3-4c0e-a64c-545310ab4b81)

---


## ✅ Comentarios finales

### 🔍 Conclusiones

* Este laboratorio expone una vulnerabilidad severa causada por la aceptación de tokens JWT con el algoritmo `none`, lo que permite eludir completamente la verificación criptográfica de la firma.
* El servidor confía ciegamente en el campo `alg` del header del JWT, permitiendo a un atacante suprimir la firma y modificar el contenido del token.
* Esto habilita la suplantación de usuarios y el acceso no autorizado a funcionalidades administrativas.

### 💡 Recomendaciones

* **Nunca permitir `alg: none`** como algoritmo de firma.
* Configurar las bibliotecas JWT para que **ignoren el valor del header `alg`** y usen solo algoritmos predefinidos del lado del servidor.
* Validar siempre la firma del token con claves seguras y adecuadas.
* Implementar listas blancas de algoritmos permitidos (por ejemplo, solo `HS256` o `RS256`).

### 📚 Lecciones aprendidas

* El header del JWT puede ser manipulado por el cliente; no debe ser considerado confiable.
* Permitir algoritmos no seguros como `none` expone a la aplicación a bypass total de autenticación.
* Es fundamental entender cómo funcionan internamente las bibliotecas JWT utilizadas para evitar errores de configuración críticos.

---



