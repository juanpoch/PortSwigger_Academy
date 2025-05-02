# Lab: User ID controlled by request parameter

This lab has a horizontal privilege escalation vulnerability on the user account page.

To solve the lab, obtain the API key for the user `carlos` and submit it as the solution.

You can log in to your own account using the following credentials: `wiener:peter`

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---


Iniciamos el lab y nos encontramos con una aplicación de shopping:
![image](https://github.com/user-attachments/assets/fd95ec2f-6af1-43ba-810b-0af116547498)
![image](https://github.com/user-attachments/assets/6d0dda0d-f553-4279-b7fa-bbf2797db441)


Ingresamos al panel de login usando el botón `My account`:
![image](https://github.com/user-attachments/assets/20cc0238-35d7-4f12-ba1e-1433ed0ac627)
![image](https://github.com/user-attachments/assets/83375af0-ab4f-4444-a47e-0662040b0f13)


Nos logueamos usando nuestras credenciales `wiener:peter`:
![image](https://github.com/user-attachments/assets/17c99f31-afc4-4c96-bd92-be032649f437)

Nos redirige al dashboard de `wiener` mediante el endpoint `/my-account?id=wiener`:
![image](https://github.com/user-attachments/assets/54c8afe9-8d95-4672-9c30-5130071fb021)

Vemos que controlamos el parámetro `id`, el cual nos devuelve la API Key del usuario.

Enviamos la petición al `Repeater` y cambiamos el valor del parámetro `id` por el de `carlos`:
![image](https://github.com/user-attachments/assets/d5d89455-6f97-49da-ac61-91d0faf3d48d)

Permitir el acceso a `/my-account?id=carlos` sin verificar si el usuario autenticado corresponde al ID solicitado es una falla de control de acceso horizontal.
La API key es un dato altamente sensible. Mostrarla en el frontend sin ningún tipo de cifrado o restricción es un riesgo grave.

Resolvemos el laboratorio brindando la API Key de carlos `pWNYPEwfSAdlcnvpSgat6FNd679Jvzfd`:
![image](https://github.com/user-attachments/assets/17e0c910-d89f-424b-998d-05bc2736339d)

---

## ✅ Conclusión

Se identificó una vulnerabilidad de **IDOR** en el parámetro `id` del endpoint `/my-account`. Esto permitió acceder a recursos sensibles de otros usuarios autenticados, violando los controles de acceso horizontales.

La aplicación no verifica si el usuario autenticado coincide con el valor del parámetro `id`, permitiendo así que cualquier usuario autenticado acceda a los datos de otros usuarios.

---

## 🛡️ Recomendaciones

- Implementar validaciones del lado del servidor para que los usuarios **solo puedan acceder a sus propios recursos**, ignorando cualquier parámetro controlado por el cliente que haga referencia a identificadores sensibles.

- Evitar exponer datos críticos como **API Keys directamente en el frontend**. Si es necesario, deben mostrarse mediante endpoints autenticados con lógica de acceso robusta.

- **No confiar nunca en datos del cliente (como cookies, headers, parámetros de URL) para decisiones de autorización.**

---

## 📚 Lecciones aprendidas

- Un parámetro aparentemente inofensivo como `?id=wiener` puede ser el vector de una vulnerabilidad seria si el backend no realiza la validación adecuada.

- Las vulnerabilidades de tipo **IDOR** son comunes, simples de explotar y pueden tener **impacto crítico** si exponen información sensible o permiten acciones sobre recursos de otros usuarios.

- El hecho de que una funcionalidad no esté visible en la UI no implica que esté protegida. **El control de acceso debe implementarse siempre del lado servidor**.







