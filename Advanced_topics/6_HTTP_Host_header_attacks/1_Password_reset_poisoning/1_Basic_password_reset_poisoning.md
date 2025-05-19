# Lab: Basic password reset poisoning

This lab is vulnerable to password reset poisoning. The user `carlos` will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account.

You can log in to your own account using the following credentials: `wiener:peter`. Any emails sent to this account can be read via the email client on the exploit server.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Accedemos al laboratorio y nos encontramos con un blog público:
![image](https://github.com/user-attachments/assets/55bedd8d-a7b8-4161-b198-e18a7f08cb13)

Sabemos que este laboratorio es vulnerable a `Password reset poisoning`, por lo que nos dirigimos a `My account` y luego al endpoint `/forgot-password` a través de la funcionalidad `Forgot password?`:
![image](https://github.com/user-attachments/assets/8caf7eb8-5049-43b0-8398-d10e3f5fd7a4)

Nos pide un mail o un usuario, brindamos nuestro usuario `wiener` para inspeccionar la funcionalidad:

![image](https://github.com/user-attachments/assets/bb346bd1-2ddd-4406-98a5-ed16d4e597e8)


Para ir a nuestro mail, hacemos clic en `Go to exploit server` y luego en `Email client`:
![image](https://github.com/user-attachments/assets/6149ed66-512f-4dd3-bf22-b621f730dd8f)

Nos brindan el siguiente link de reseteo de contraseña: `https://0ac100a704c1804b81d24d410085003f.web-security-academy.net/forgot-password?temp-forgot-password-token=77l5fug8sqa3wxpg7kqvnrxshwochbm8`

Ingresamos la nueva contraseña y la cambiamos:
![image](https://github.com/user-attachments/assets/d2f80e12-44e5-4f02-9726-822b02dd6289)

Intentamos reutilizar el token pero vemos que el mismo se invalida correctamente:
![image](https://github.com/user-attachments/assets/2e947407-7979-45d1-885e-3260b9815d5e)


Hasta ahora tenemos el siguiente flujo:
- El usuario envía su correo o nombre de usuario.
- El sitio genera un token único y lo asocia a la cuenta.
- El sitio envía al email del usuario un enlace con el token
- El usuario hace clic, cambia su contraseña, y el token se invalida.



---

Ya conocemos el flujo de cambio de contraseña. Nosotros no tenemos el email de la víctima, pero el flujo se puede iniciar brindando su nombre de usuario `carlos`. Enviamos al Repeater la petición POST del endpoint `/forgot-password` y vemos que podemos realizar un `HTTP Host header attack`:
![image](https://github.com/user-attachments/assets/a9248861-5fe7-4087-a573-07afbb293e2d)

Cambiamos el valor del Header `Host` por `test` y cuando accedemos a nuestro email client, observamos que el link se construye con el valor `test` del header `Host`.

Procedemos a generar una nueva petición, pero esta vez el valor de la cabecera Host será el de nuestro Exploit server (`exploit-0a1c00bf04ef8068817a4cfb01a9009c.exploit-server.net`):
![image](https://github.com/user-attachments/assets/47bd1087-5909-41f9-a816-5cfeeea42b30)

Esto enviará un link al mail del usuario carlos con la siguiente estructura:
`https://exploit-0a1c00bf04ef8068817a4cfb01a9009c.exploit-server.net/forgot-password?temp-forgot-password-token=...`

📌 En este punto, inyectamos un valor controlado en el header `Host` para que el servidor genere un link de reseteo con un dominio malicioso. Cuando el usuario Carlos haga clic, el token quedará expuesto en nuestro exploit server.

Nos dirigimos a nuestro Exploit server y accedemos a `Access log`:
![image](https://github.com/user-attachments/assets/98f45d5e-3d44-4af7-922e-72728c9be822)

Esto indica que el usuario carlos hizo clic en el link para acceder al endpoint de cambio de contraseña, pero como la url no es válida recibió un código de estado 404.

Pero nosotros conocemos el verdadero endpoint de reseteo de contraseña, y ahora tenemos el token temporal: `gvva9liyrlzzlpxumnwjg02524w6iqbz`

Si accedemos a nuestro email client, obtenemos el verdadero endpoint de reseteo:
![image](https://github.com/user-attachments/assets/50aa0747-253f-4fd5-9877-fe61c7fc0073)

Lógicamente tenemos que usar el nuevo token temporal:
![image](https://github.com/user-attachments/assets/3ef6b8d8-2590-4f15-9b12-199c76acb311)

Tenemos que usar los siguientes parámetros en el body:
```bash
csrf=<valor_csrf>&temp-forgot-password-token=<token>&new-password-1=<clave_nueva>&new-password-2=<clave_nueva>
```

Utilizamos los valores necesarios:
```bash
csrf=u29omivDxKaeUru2hPmB3kjn8GIuCzQj&temp-forgot-password-token=gvva9liyrlzzlpxumnwjg02524w6iqbz&new-password-1=test1234&new-password-2=test1234
```
![image](https://github.com/user-attachments/assets/dc21b7bd-eb51-444b-8192-6b499a62fe81)

Nos autenticamos como `carlos:test1234` y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/be3fa8a4-16a5-4df5-9630-e091d9461802)

---

---

## ✅ Conclusiones

- La aplicación **construye URLs absolutas** para restablecer contraseñas tomando el valor del header `Host`, el cual es **controlable por el usuario**.
- No valida contra una **whitelist de dominios permitidos**, lo que permite redireccionar tokens a un servidor controlado por el atacante.
- Aprovechamos este comportamiento para que la víctima, al hacer clic en el link enviado por email, **envíe su token al servidor del atacante**.
- Con el token en nuestro poder, pudimos **resetear la contraseña** de la víctima (`carlos`) y acceder a su cuenta.

---

## 🛡️ Recomendaciones

- **Evitar usar `Host` directamente** para construir URLs absolutas. Preferir siempre valores configurados manualmente desde archivos de configuración.
- **Validar el header `Host`** contra una lista de dominios explícitamente permitidos (por ejemplo, usando `ALLOWED_HOSTS` en Django).
- **No incluir tokens sensibles en enlaces** generados dinámicamente con entradas del usuario.
- **Separar el entorno de generación de correos** del de procesamiento de peticiones web, y restringir los orígenes válidos para redirecciones o URLs.

---

## 📚 Lecciones aprendidas

- El header `Host` puede ser una fuente peligrosa si se usa sin validación.
- Los usuarios muchas veces confían en enlaces dentro de correos legítimos, por lo que **el control del dominio del enlace** es crítico.
- Incluso una funcionalidad segura como el reset de contraseña puede ser explotada si **se combina con una mala práctica de generación de URLs**.

---

