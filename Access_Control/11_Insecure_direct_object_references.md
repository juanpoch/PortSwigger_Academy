# Lab: Insecure direct object references

This lab stores user chat logs directly on the server's file system, and retrieves them using static URLs.

Solve the lab by finding the password for the user `carlos`, and logging into their account.

---

## Exploring the `Live Chat` Functionality

### Interactive Chat Feature
We accessed the `live chat` functionality and observed that it includes an interactive chat feature:

![Interactive Chat](https://github.com/user-attachments/assets/bd28e2d6-2365-4d22-9b6c-a829e6ed30aa)

### Transcript Download
The chat interface provides a `view transcript` feature that allows users to download a file containing the chat transcript:

![Transcript Download Option](https://github.com/user-attachments/assets/dc723cb8-383c-4bff-b252-3e2a24f80909)

---

## Identifying an IDOR Vulnerability
Upon inspecting this feature, we hypothesized that it might be vulnerable to an **Insecure Direct Object Reference (IDOR)**. To test this, we modified the parameter controlling which file is downloaded:

![Parameter Tampering](https://github.com/user-attachments/assets/dd95f682-0691-4c07-90b1-03cb7e917ae7)

As a result, we successfully retrieved sensitive information, including a password.

---

## Logging in as `carlos`
Using the retrieved credentials, we logged in as the user `carlos`:

![Login as Carlos](https://github.com/user-attachments/assets/f1207647-3ade-45be-a6b7-6a7af664a379)

We then applied the received cookie to gain access to Carlos' home page:

![Carlos' Home Page](https://github.com/user-attachments/assets/435e6756-b729-46c3-95fa-b773f16699c1)  
![Carlos' Dashboard](https://github.com/user-attachments/assets/2c5e88b6-603b-4154-bea9-4d95cfbed1de)




