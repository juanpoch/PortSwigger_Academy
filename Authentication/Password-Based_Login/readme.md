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

We made the request using `cURL`:
![image](https://github.com/user-attachments/assets/7d7cb48f-a367-4e11-99be-2af01de098ae)

We performed fuzzing with `ffuf`:
![image](https://github.com/user-attachments/assets/92663fd5-71d1-47f1-b19e-ef859092eec7)

We see that the user is **vagrant**.  

As an alternative, we try fuzzing again but filtering with a regex that exactly matches that string. We created a bash script:"
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


We run the script:  
![image](https://github.com/user-attachments/assets/361d0727-cd11-4583-8880-b7db34e9c7c4)

We could also have used BurpSuite's Intruder:
First, we need to add the payload, include the wordlist, and in **settings** we need to configure the `GREP-EXTRACT` section:
![image](https://github.com/user-attachments/assets/a188d900-d951-4db7-9b24-40a3d29677ed)
![image](https://github.com/user-attachments/assets/da809777-e29d-41cb-be7c-6565cf0ae109)



Now that we have the **vagrant** user, we make a `cURL` request with a test password to observe the behavior:"
![image](https://github.com/user-attachments/assets/0b0e5995-aa3e-468c-b4ac-eb0c075adaa0)
We see that a '.' is missing at the end of the sentence. Now, we perform password fuzzing and filter **Invalid username or password**:  
![image](https://github.com/user-attachments/assets/3bae9716-68c4-4193-b2ff-fad2a13e83c7)

Now we log in with the credentials and solve the lab:
![image](https://github.com/user-attachments/assets/f22cc318-f15b-4e2d-80fc-98d05df8cca2)









