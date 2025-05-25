# Lab: OS command injection, simple case

This lab contains an OS command injection vulnerability in the product stock checker.

The application executes a shell command containing user-supplied product and store IDs, and returns the raw output from the command in its response.

To solve the lab, execute the `whoami` command to determine the name of the current user.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green)  


---

Iniciamos el laboratorio y tenemos una aplicación de compra de productos.
![image](https://github.com/user-attachments/assets/0d882c22-fac2-41c0-b131-7a1750ccb4cb)


Los productos pueden visualizarse con sus características principales (imagen, precio, etc) y también se puede acceder a más información a través del botón `View details`:
![image](https://github.com/user-attachments/assets/3f0b3c9a-a056-44c6-b48d-788efa4a7c0e)

También vemos que tenemos la funcionalidad `Check stock`.

Para analizarla, capturamos la petición con `Burp Suite`:
![image](https://github.com/user-attachments/assets/ac1a5dae-a0ae-4f07-8412-bf9975403980)

Vemos que se tramita una solicitud `POST` al endpoint `/product/stock` y en el cuerpo de la solicitud se tramita el parámetro `productId=1&storeId=1`.

Aquí estamos consultando el stock de un producto en una sucursal específica mediante la siguiente url:
 ```url
https://url-vuln/product/stock
```

Suponiendo que en el backend, se ejecuta un comando a nivel de sistema operativo para consultar el stock:
```bash
stockreport.sh 1 1
```

Enviamos la solicitud al repeater, y en el inspector, visualizamos la sección `Request body parameters`, hacemos click en `>` para editar los parámetros que vamos a tramitar:
![image](https://github.com/user-attachments/assets/3b7898e2-ccc9-4107-be3f-d7b874077b95)

Insertamos un payload de prueba `& echo test &`, hacemos click en `Apply changes` y enviamos la solicitud:
![image](https://github.com/user-attachments/assets/9505e8dd-a4d9-49b5-9916-46f95d301ac7)

Vemos que la cadena `test` es devuelta por el servidor, por lo que confirmamos que tenemos ejecución remota de comandos.

Si intentamos inyectar el mismo payload en el primer parámetro (`productId`) vemos que lanza el siguiente error:
![image](https://github.com/user-attachments/assets/5e865f3c-024a-40c9-b56d-1cc290e9707a)

A nivel backend estamos intentando ejecutar el siguiente comando:
```bash
stockreport.sh 1 & echo test & 1
```

Esto ejecutaría tres comandos separados:

- `stockreport.sh 1` (el comando original, pero incompleto o inválido).

- `echo test` (el comando inyectado, para comprobar si se ejecuta).

- `1` (se intenta ejecutar como comando, lo cual debería fallar).

Luego tenemos la respuesta del servidor:
```text
sh: 1: /home/peter-F0lj21/stockreport.sh: line 5: $2: unbound variable
1: not found
```

- El script `stockreport.sh` fue ejecutado con argumentos mal formados, lo cual causó un error en `$2` (esperaba `productId` y `storeId`, pero la estructura se rompió por la inyección).

- `1`: not found indica que se intentó ejecutar 1 como comando. Esto confirma que la shell está interpretando los & como separadores y está tratando cada segmento como un comando separado.
- También vemos en el error, el nombre del home directory del usuario: `/home/peter-F0lj21`.

Si bien tenemos una vulnerabilidad de inyección, no se mostró la salida del comando `echo test`.

Inyectamos el comando `whoami` en el segundo parámetro y resolvemos el lab:

![image](https://github.com/user-attachments/assets/594c7869-022a-4e04-8c76-ddb45103a550)

![image](https://github.com/user-attachments/assets/29bcd285-ffad-447a-98c8-b5c5979ea589)


---

### 📌 Conclusión

Este laboratorio demuestra cómo una aplicación que construye comandos del sistema a partir de parámetros del usuario puede ser vulnerable a **OS command injection**, permitiendo ejecutar comandos arbitrarios en el servidor.

Al inyectar comandos como `& echo test &` o `& whoami &`, comprobamos que el servidor no filtra ni valida adecuadamente la entrada, y ejecuta directamente los comandos proporcionados.

Incluso cuando el primer argumento está mal formado (`productId`), logramos ejecutar código aprovechando el segundo argumento (`storeId`), mostrando cómo pequeñas modificaciones pueden alterar el flujo de ejecución.

---

### 🛡️ Recomendaciones de mitigación

- **Evitar concatenar entrada del usuario en comandos del sistema.**
- Usar funciones seguras del lenguaje de programación, como `subprocess.run(..., shell=False)` en Python.
- Validar estrictamente los parámetros permitidos mediante listas blancas.
- Ejecutar procesos con permisos mínimos para reducir el impacto de una posible explotación.















