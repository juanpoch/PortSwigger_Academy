# 🔐 Password Reset Poisoning

La técnica de **Password Reset Poisoning** permite a un atacante manipular un sitio vulnerable para que genere un **enlace de restablecimiento de contraseña apuntando a un dominio controlado por él**. Esto puede ser aprovechado para robar el token secreto necesario para cambiar la contraseña de otros usuarios.

---

[Técnica documentada por James Kettle](https://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html)

---
## 🔎 ¿Cómo funciona un restablecimiento de contraseña normal?

1. El usuario envía su correo o nombre de usuario.
2. El sitio genera un token único y lo asocia a la cuenta.
3. El sitio envía al email del usuario un enlace con el token:

```
https://example.com/reset?token=abc123
```

4. El usuario hace clic, cambia su contraseña, y el token se invalida.

Todo esto **asume que solo el usuario puede acceder a su correo**, y que **el enlace lleva al dominio correcto**.

---

## ⚠️ ¿Cuándo es vulnerable?

Si el sitio genera el enlace usando valores controlables por el atacante (por ejemplo, el **encabezado Host**), entonces es vulnerable:

```
Host: evil-attacker.com
```

Esto podría generar un enlace como:

```
https://evil-attacker.com/reset?token=abc123
```

---

## 🤪 Ataque paso a paso

1. El atacante conoce el email de la víctima y solicita un reseteo de contraseña.
2. Intercepta la solicitud y cambia el Host por su propio dominio:

```
Host: evil-user.net
```

3. La víctima recibe un email real con el siguiente enlace:

```
https://evil-user.net/reset?token=0a1b2c3d...
```

4. Si la víctima hace clic (o el token es precargado por antivirus, proxy, etc), el token se filtra al atacante.
5. El atacante lo usa en el sitio legítimo:

```
https://vulnerable.com/reset?token=...
```

6. Cambia la contraseña de la víctima y compromete la cuenta.

---

## 🔓 Condiciones necesarias para explotar

| Requisito                             | Descripción                                                       |
| ------------------------------------- | ----------------------------------------------------------------- |
| Uso del header `Host` o similar       | El servidor usa `Host` para construir el link.                    |
| No validación de dominios permitidos  | El backend no verifica que `Host` sea un dominio legítimo.        |
| El token no está vinculado al dominio | El token es válido incluso si fue enviado desde un dominio falso. |

---

## ⚖️ Prevención

* **Evitar usar el header Host** para construir URLs absolutas.
* Usar **URLs relativas** siempre que sea posible.
* Configurar el dominio legítimo en un archivo de configuración.
* Validar que `Host` coincida con una **lista blanca de dominios válidos**.
* Rechazar encabezados como `X-Forwarded-Host` si no son necesarios.
* No alojar sitios internos y externos en el mismo servidor.

---

## 🎓 Laboratorios disponibles

[Lab: Basic password reset poisoning](1_Basic_password_reset_poisoning.md)  

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

✅ **Resumen:** Password Reset Poisoning explota la confianza indebida en el encabezado `Host`. Con solo interceptar y modificar la solicitud, el atacante puede robar el token de reseteo y secuestrar cuentas de otros usuarios. Una validación adecuada de los encabezados y configuraciones robustas son esenciales para prevenir este ataque.
