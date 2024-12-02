# Lab: Username enumeration via different responses

 This lab is vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

- Candidate usernames
- Candidate passwords

To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

The lab features the following login panel:

![image](https://github.com/user-attachments/assets/8b597411-b722-4965-9593-5e6e5ea5e05e)

We attempted to log in with test credentials:
![image](https://github.com/user-attachments/assets/e3129c73-ac3b-4142-b33d-63643ff746f6)

We perform fuzzing with `ffuf` using the `candidate_usernames.txt` wordlist provided by **PortSwigger**:  
![image](https://github.com/user-attachments/assets/3798bbce-e4ba-4fb3-a098-fa8b3db6f6d6)

Now that we have the username, we perform the login again with `cURL` to observe the behavior:
![image](https://github.com/user-attachments/assets/00faf889-916a-4195-9ee2-ac4f0a662914)

We make the request again with `ffuf`, now filtering "Incorrect password" using the `candidate_passwords.txt` wordlist:
![image](https://github.com/user-attachments/assets/7a96bbf0-b102-4106-b4f7-26e2cd420ebc)

We log in and complete the lab:
![image](https://github.com/user-attachments/assets/5bdb1043-84b8-4998-943b-4ca10775c9c7)
