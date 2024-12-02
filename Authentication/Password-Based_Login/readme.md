# Vulnerabilities in password-based login

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
