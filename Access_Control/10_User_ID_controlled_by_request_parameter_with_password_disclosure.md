# Lab: User ID controlled by request parameter with password disclosure

This lab has user account page that contains the current user's existing password, prefilled in a masked input.

To solve the lab, retrieve the administrator's password, then use it to delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

---

# Lab Report: Exploiting Vulnerabilities in Login and Admin Panels

## Logging in as `wiener`
We begin by logging in as the user `wiener`:

![Login Page](https://github.com/user-attachments/assets/30cfa370-408b-4b12-bea1-d76826f7746e)

After logging in, we are redirected to the home page, which includes a feature to change our password. The panel displays our current password in a hidden format:

![Home Page](https://github.com/user-attachments/assets/30da7f4a-bae6-4588-a1ca-2edf981c5240)

We send the request to the repeater tool and analyze its structure:

![Request Inspection](https://github.com/user-attachments/assets/305b3b09-2287-4f41-8a72-59274319858c)

By performing parameter tampering, we successfully retrieve the password:

![Password Revealed](https://github.com/user-attachments/assets/879f43c1-6697-4197-8d27-1cf7097c961e)

---

## Logging in as `administrator`
Next, we aim to log in as the `administrator`. To do this, we extract the necessary cookies and CSRF token from the `/login` panel using a `GET` request:

![GET Request for Cookies and CSRF Token](https://github.com/user-attachments/assets/bd642577-b633-4ccc-8374-963dc8dba259)  
![CSRF Token Extracted](https://github.com/user-attachments/assets/2159114e-883a-4f8c-a100-2da7e9313439)

After sending the login request, we receive a new cookie for the redirect:

![Redirect Cookie](https://github.com/user-attachments/assets/628165b5-d4d8-4afa-b603-3d5f95fddfed)

Once logged in, we access the administrator's home page:

![Administrator Home Page](https://github.com/user-attachments/assets/b93772b7-6cab-465c-bffb-cf3166b2f13e)

On this page, we find a link to the `/admin` panel:

![Admin Panel Link](https://github.com/user-attachments/assets/13323e87-326f-4b39-8eae-c1d3a00a9fc6)

---

## Accessing the `/admin` Panel
We navigate to the `/admin` panel:

![Admin Panel](https://github.com/user-attachments/assets/937d55c5-8ddd-44f1-9361-424a26fde584)

---

## Deleting Carlos' Account
To complete the lab, we send a `GET` request to the specified endpoint to delete Carlos' account:

![Request to Delete Carlos](https://github.com/user-attachments/assets/70326b83-da1f-43fd-85ca-b264969c668d)

Finally, the lab is marked as resolved:

![Lab Resolved](https://github.com/user-attachments/assets/957d9b5d-4660-4ee3-963d-4ebdd1b5dd28)













