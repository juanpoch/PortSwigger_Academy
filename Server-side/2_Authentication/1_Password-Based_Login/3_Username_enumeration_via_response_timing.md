# Lab: Username enumeration via response timing

This lab is vulnerable to username enumeration using its response times. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

- `Your credentials`: `wiener`:`peter`
- [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

`Hint`: To add to the challenge, the lab also implements a form of IP-based brute-force protection. However, this can be easily bypassed by manipulating HTTP request headers. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-blue)  

---

Iniciamos el laboratorio y nos encontramos con un blog:

<img width="1874" height="751" alt="image" src="https://github.com/user-attachments/assets/ed9d7095-9bed-4e4f-a819-0074acfd27ad" />

Nos dirijimos a `My account` para inspeccionar el panel de login:
<img width="1887" height="810" alt="image" src="https://github.com/user-attachments/assets/cfb9e4fa-a4a4-42e3-bf08-2c15c04e2b0d" />

Realizamos una petición con credenciales de prueba para analizar el comportamiento cuando el usuario es inválido:
<img width="1916" height="874" alt="image" src="https://github.com/user-attachments/assets/418af68c-d51d-46b6-bace-b3e1a10e2239" />

Vemos que la respuesta tarda 235 millis en llegar.

Ahora probamos con un usuario válido:

<img width="1915" height="870" alt="image" src="https://github.com/user-attachments/assets/5e540710-2058-499d-8ef3-877399c1ffb6" />

Tenemos un tiempo de 252 millis, lo que no es una diferencia significativa.

Vemos que si probamos 3 veces nos bloquean:
<img width="1908" height="852" alt="image" src="https://github.com/user-attachments/assets/8724bf35-2886-408f-87e5-bfb5a6537c2d" />

Procedemos a utilizar el header `X-Forwarded-For`:

<img width="833" height="253" alt="image" src="https://github.com/user-attachments/assets/601885e6-c8b2-4c36-8ad0-fc7be14e8516" />

Probamos una vez y vemos que estamos habilitados nuevamente para autenticarnos:
<img width="1882" height="713" alt="image" src="https://github.com/user-attachments/assets/2a1805db-0620-4912-ad6f-4766ec88d100" />

Al tercer intento nos vuelve a bloquear:
<img width="1912" height="738" alt="image" src="https://github.com/user-attachments/assets/da9657de-b867-4168-965f-c75de7673b7f" />

Entonces cambiamos nuevamente el valor del header `X-Forwarded-For` y vemos que nuevamente podemos intentar autenticarnos:
<img width="1501" height="691" alt="image" src="https://github.com/user-attachments/assets/314859cb-f699-4dcf-b565-7b6c2911c80e" />

Continuamos con nuestro análisis. Lo que hacemos es probar si la aplicación valida primero si el usuario es correcto antes de validar la contraseña. Si esto fuese cierto, podríamos enumerar usuarios mediante diferencias en los tiempos de respuesta.

La lógica del ataque es probar usuario válido primero con contraseña extensa y luego comparar con los tiempos de respuesta de un usuario inválido con contraseña extensa.

- Probamos con usuario correcto y contraseña extensa:
<img width="1910" height="849" alt="image" src="https://github.com/user-attachments/assets/b5650ccb-6828-4f43-a60e-6c9af608168b" />

Tarda 3123 millis, lo que es un indicativo de que la aplicación podría ser vulnerable a este ataque.

- Probamos con usuario incorrecto y contraseña extensa:
<img width="1915" height="845" alt="image" src="https://github.com/user-attachments/assets/f59294f0-cfa9-42e9-a6b3-c6c554a328e8" />


Acabamos de comprobar que el servidor primero valida si el usuario es correcto, de lo contrario no valida la contraseña, por lo cual el tiempo de respuesta es menor que cuando el usuario es correcto.


Procedemos a realizar un ataque de enumeración de usuarios utilizando el `Intruder` con un ataque `Pitchfork` el cual utilizaremos dos posiciones de payload con 2 wordlist que avanzan en paralelo.

- Payload 1 itera del número 6 al 106 para valores del header `X-Forwarded-For`, lo cual cambiaría la dirección IP por cada petición, 100 veces a lo largo del ataque, ya que tenemos una wordlist de 101 usuarios:
<img width="1883" height="937" alt="image" src="https://github.com/user-attachments/assets/d25bf91f-6199-45b3-b2d3-a4e33a605356" />

- Payload 2 itera a través de la wordlist de usernames:
<img width="1876" height="894" alt="image" src="https://github.com/user-attachments/assets/fc2b58d9-21cf-4408-96e3-31cffcf337ef" />

Realizamos el ataque y vemos que en la columna `Response receive` obtenemos un tiempo de respuesta alto para el payload `at`, lo que nos indica que es un usuario válido:
<img width="1865" height="786" alt="image" src="https://github.com/user-attachments/assets/f1f97e65-04d2-4391-9571-94fa4724d114" />


El siguiente paso es realizar un ataque de fuerza bruta de contraseñas utilizando el usuario `at`.

Payload 1:
<img width="1877" height="894" alt="image" src="https://github.com/user-attachments/assets/7e11f3c7-28bf-4916-9e02-d343e8b840a9" />

Payload 2 utilizamos la wordlist de contraseñas:
<img width="1879" height="859" alt="image" src="https://github.com/user-attachments/assets/8cbdb7bb-f67d-44f4-8615-26c20e47c1af" />


Obtenemos un código de estado `302` que nos redirecciona a `my-account?id=at` lo que nos indica una autenticación exitosa:
<img width="1862" height="630" alt="image" src="https://github.com/user-attachments/assets/7f04371f-b1c9-4f8b-9977-92fd366ab665" />


Nos autenticamos con las credenciales `at`:`123qwe` y resolvemos el laboratorio:
<img width="1680" height="746" alt="image" src="https://github.com/user-attachments/assets/8acad802-204e-45bf-b451-5948470d1a85" />

