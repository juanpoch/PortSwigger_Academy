# Vulnerabilities in password-based login

## Lab: Username enumeration via different responses

 This lab is vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

- Candidate usernames
- Candidate passwords

To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

The lab features the following login panel:

![image](https://github.com/user-attachments/assets/8b597411-b722-4965-9593-5e6e5ea5e05e)

We attempted to log in with test credentials:
![image](https://github.com/user-attachments/assets/e3129c73-ac3b-4142-b33d-63643ff746f6)

We perform fuzzing with `ffuf` using the `candidate_usernames.txt` wordlist provided by **PortSwigger**:  
![image](https://github.com/user-attachments/assets/3798bbce-e4ba-4fb3-a098-fa8b3db6f6d6)

Now that we have the username, we perform the login again with `cURL` to observe the behavior:
![image](https://github.com/user-attachments/assets/00faf889-916a-4195-9ee2-ac4f0a662914)

We make the request again with `ffuf`, now filtering "Incorrect password" using the `candidate_passwords.txt` wordlist:
![image](https://github.com/user-attachments/assets/7a96bbf0-b102-4106-b4f7-26e2cd420ebc)

We log in and complete the lab:
![image](https://github.com/user-attachments/assets/5bdb1043-84b8-4998-943b-4ca10775c9c7)


## Lab: Username enumeration via subtly different responses

 This lab is subtly vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

- Candidate usernames
- Candidate passwords

To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page. 

Realizamos la petición mediante `cURL`:
![image](https://github.com/user-attachments/assets/7d7cb48f-a367-4e11-99be-2af01de098ae)

Realizamos fuzzing con `ffuf`:
![image](https://github.com/user-attachments/assets/5d04dea3-24ac-454f-ad4f-fba32820b6f2)
No encontramos nada, intentamos volver a hacer fuzzing pero filtrando con una regex que coincida exactamente con ese string, realizamos un script en bash:
```bash
#!/bin/bash

WORDLIST="candidate_usernames.txt"

URL="https://0a5d00730450e252d7fd8d9d006400f4.web-security-academy.net/login"

HEADERS="Content-Type: application/x-www-form-urlencoded"

while read -r USER; do
    # Enviar la solicitud con curl
    RESPONSE=$(curl -s -X POST "$URL" \
        -H "$HEADERS" \
        -d "username=$USER&password=test")

    if [[ "$RESPONSE" != *"Invalid username or password."* ]]; then
        echo "Posible usuario válido: $USER"
    fi
done < "$WORDLIST"
```


Ejecutamos el script:
![image](https://github.com/user-attachments/assets/361d0727-cd11-4583-8880-b7db34e9c7c4)

Ahora que tenemos el usuario **vagrant** realizamos una petición por `cURL` con password de prueba para observar el comportamiento:
![image](https://github.com/user-attachments/assets/0b0e5995-aa3e-468c-b4ac-eb0c075adaa0)
Vemos que falta un "." al final de la oración.
Ahora realizamos fuzzing de passwords y filtramos **Invalid username or password**:  
![image](https://github.com/user-attachments/assets/3bae9716-68c4-4193-b2ff-fad2a13e83c7)










