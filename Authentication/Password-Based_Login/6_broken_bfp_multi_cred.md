# Lab: Broken brute-force protection, multiple credentials per request

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
