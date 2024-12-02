# Lab: Username enumeration via account lock

This lab is vulnerable to username enumeration. It uses account locking, but this contains a logic flaw. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

Wordlists:
- Candidate usernames
- Candidate passwords

We first perform a `cURL` inspection with test credentials:
![image](https://github.com/user-attachments/assets/718b2233-0db5-455d-8d43-c71a0a93876c)

Next, we perform fuzzing with `ffuf` to enumerate valid usernames. We run `ffuf` 3 or 4 times until we get a different response:
![image](https://github.com/user-attachments/assets/1e5b8d71-5fd9-49a4-bfe7-42bc104cbb83)
This happens because the server blocks the account after the third failed login attempt, allowing enumeration of the blocked user:
![image](https://github.com/user-attachments/assets/ecc6a897-a05d-4e18-9938-6471787bd25d)

We then perform a password brute-force attack using this user:
![image](https://github.com/user-attachments/assets/bd3496b1-4949-4f46-8219-1738c3abc796)

We create a small password file with these passwords and attempt the attack again after waiting for one minute:
![image](https://github.com/user-attachments/assets/c14920ba-76e1-4ee6-a3d4-b7c7a1c57cae)


Finally, we log in and complete the lab:
![image](https://github.com/user-attachments/assets/8da90fcb-de49-4413-b4a1-604898b3e1e0)

**Note:**  
We could also use Burp Suite Intruder:  
![image](https://github.com/user-attachments/assets/177fe106-2767-4247-bd42-d1dd381a5079)
