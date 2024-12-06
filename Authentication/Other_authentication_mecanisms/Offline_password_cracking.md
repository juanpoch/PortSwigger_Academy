# Lab: Offline password cracking

 This lab stores the user's password hash in a cookie. The lab also contains an XSS vulnerability in the comment functionality. To solve the lab, obtain Carlos's stay-logged-in cookie and use it to crack his password. Then, log in as carlos and delete his account from the "My account" page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`



We go to the comments section and there's a form, we try `XSS` injection:
![image](https://github.com/user-attachments/assets/2207c88d-1c22-4db7-84ba-be7754c5618e)

![image](https://github.com/user-attachments/assets/644675d8-c7d1-4b3d-84eb-a6596dc2c159)

Now we inject a `cookie hijacking` payload. If we go to `Go to exploit server`, we get the server URL, which we include in the payload:
![image](https://github.com/user-attachments/assets/8f0eb768-51ed-40a1-a41c-19d0ea63c0f1)
![image](https://github.com/user-attachments/assets/6d42da55-3316-41cb-b9c6-af596d6123ed)

Then we go to the server and click on `Access Log`:
![image](https://github.com/user-attachments/assets/ad5e3bdf-6039-4748-9999-332a7e4e2abf)

![image](https://github.com/user-attachments/assets/f5169898-388c-49af-a9de-6fd7df68af99)

We crack the hash:
![image](https://github.com/user-attachments/assets/805ac6f0-2173-43ad-a492-4826ec8efd18)

Then we log in with Carlos's account and delete it:
![image](https://github.com/user-attachments/assets/fb0c06aa-75b9-4745-9413-758029738326)




