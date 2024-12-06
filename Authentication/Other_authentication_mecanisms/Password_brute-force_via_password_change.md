# Lab: Password brute-force via password change

 This lab's password change functionality makes it vulnerable to brute-force attacks. To solve the lab, use the list of candidate passwords to brute-force Carlos's account and access his "My account" page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`
- Wordlist: `Candidate passwords`

---

# Password Manipulation and Brute-Force Attack Flow:

---

### Logging in reveals a panel for changing the password. We attempt to change it using the correct current password to observe the server's response:
![image](https://github.com/user-attachments/assets/d00efd0c-fed9-4d59-b38c-a9ba5bb59063)

---

### Next, we try again but with an incorrect current password:
![image](https://github.com/user-attachments/assets/c8b8a799-bc0c-49ce-b557-ebb3c3c189b7)

---

### After logging in again with the correct password, the server informs us that we have made too many failed attempts:
![image](https://github.com/user-attachments/assets/a517f74f-fc31-4860-a600-f92ada3dc026)

---

### This confirms that attempting to change the password with an incorrect `current password` logs us out and blocks us for 1 minute.

---

### Given that the `username` parameter is under our control and the server's responses differ based on whether the entered password is correct, we attempt a brute-force attack on the password for `carlos`.

### As expected, this yields no significant results:
![image](https://github.com/user-attachments/assets/26212399-6999-4ba0-8a82-71581187b237)

---

### Let’s reanalyze the password reset functionality.

---

### Entering the correct `current password` and two new passwords that do not match:
![image](https://github.com/user-attachments/assets/8b6b66ac-981c-4bd1-b2de-ad566da92e71)

---

### Entering the incorrect `current password` and two new passwords that do not match:
![image](https://github.com/user-attachments/assets/0707e2f1-1342-4f6e-a0ab-b132f46bca6b)

---

### The server responds with `Current password is incorrect`. This shows that the error handling allows us to perform a brute-force attack using **Burp Suite Intruder**.

---

### Configure the payload and execute a **Sniper Attack**:
![image](https://github.com/user-attachments/assets/8605cf82-e53f-4327-906a-d1023772caf3)

---

### The attack reveals the password:
![image](https://github.com/user-attachments/assets/b48a37fe-a304-4157-8841-af07e176f4b0)

---

### Log in to Carlos's account and access his "My Account" page:
![image](https://github.com/user-attachments/assets/14b6bb24-1b4c-4dcf-9652-e25afa39cbee)













