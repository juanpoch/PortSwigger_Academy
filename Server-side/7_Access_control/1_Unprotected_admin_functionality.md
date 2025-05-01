# Lab: Unprotected admin functionality

This lab has an unprotected admin panel.

Solve the lab by deleting the user `carlos`.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el lab y nos encontramos con una aplicación de shopping:
![image](https://github.com/user-attachments/assets/db28e02b-14b5-4f65-a947-79f6ce37b4ed)

El laboratorio nos dice que tenemos que encontrar un panel de administración desprotegido. En un pentesting real probablemente incurriríamos en realizar fuerza bruta para descubrir directorios, pero en este caso realizaremos una inspección manual para encontrarlo.

Primero observamos las peticiones tanto del panel principal como el de login:
![image](https://github.com/user-attachments/assets/f30e153a-2959-4911-a1cf-ce2d347e418d)

![image](https://github.com/user-attachments/assets/0b8bacf4-5a38-463e-998b-9b571a0698b8)

No encontramos enlaces ocultos ni comentarios inspeccionando las peticiones.

Procedemos a buscar el robots.txt y observamos que se lista el panel de administración:
![image](https://github.com/user-attachments/assets/9a76f9f2-8f99-40b0-8e8a-7c593ac2ca4b)

Accedemos al panel de administración sin ningún tipo de restricciones, vemos que tenemos la opción de eliminar usuarios:
![image](https://github.com/user-attachments/assets/409763ca-694d-48be-aa25-2131a278f618)

⚠️ `Análisis`: El acceso al panel administrativo sin autenticación representa un claro caso de vertical privilege escalation. Este tipo de fallo permite a usuarios no privilegiados realizar acciones sensibles, como la eliminación de cuentas.

Eliminamos el usuario `carlos` y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/10f42a11-0fe5-466c-b020-9f0c94abae76)

## ✅ Conclusión

Se identificó una funcionalidad administrativa completamente expuesta sin mecanismos de autenticación, lo que permitió realizar acciones de alto privilegio sin autorización.

## 🛡️ Recomendaciones

- Proteger todas las funcionalidades administrativas con controles de acceso robustos.
- Nunca confiar en `robots.txt` como mecanismo de ocultamiento de rutas sensibles.
- Implementar roles (RBAC) y sesiones autenticadas para limitar el acceso a usuarios con permisos adecuados.

## 📚 Lecciones aprendidas

- El archivo `robots.txt` puede convertirse en una fuente de fuga de información.
- Es importante realizar *content discovery* en pentests, incluso en entornos de producción.
- Funcionalidades críticas como el panel de administración deben requerir autenticación y validación de roles.








