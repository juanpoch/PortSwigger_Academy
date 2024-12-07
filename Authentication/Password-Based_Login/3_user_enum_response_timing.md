# Lab: Username enumeration via response timing

This lab is vulnerable to username enumeration using its response times. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

- Your credentials: `wiener:peter`  
Wordlists:
- Candidate usernames
- Candidate passwords

Hint: To add to the challenge, the lab also implements a form of IP-based brute-force protection. However, this can be easily bypassed by manipulating HTTP request headers.

We make the request with `cURL` to observe the response:
![image](https://github.com/user-attachments/assets/4b0216ad-f410-43e4-8917-8c4f35f191d3)
After a few attempts, we get the message:
![image](https://github.com/user-attachments/assets/627286b2-98df-489e-a169-4204d6d6247f)

We send the request from Burp to the Intruder and configure a Pitchfork Attack, which performs parallel fuzzing with 2 payloads:
![image](https://github.com/user-attachments/assets/10a8ff49-fdae-48cc-ad68-3c91e49fa874)
We spoof the IP with the "X-Forwarded-For" header and fuzz the username. At the same time, in `Settings`, `Grep - Match`, we configure the negative filter for the response "Invalid username or password.":
![image](https://github.com/user-attachments/assets/4bceb7ad-ce4c-4885-95b0-1f4b191697f6)
**Note:** The X-Forwarded-For (XFF) header is an HTTP header used to identify the original IP address of a client that is behind a proxy server, load balancer, or another intermediate device. It is particularly useful in architectures where the client does not connect directly to the final server.  
**Limitations:**  
Unreliable if proxies are not secure:
 - If any intermediate device can modify the header, the information can be spoofed.
 - It is recommended to use it only in networks where proxies and load balancers are trusted.
   
We see that despite applying the filter, this time there is no visible difference:
![image](https://github.com/user-attachments/assets/25e1784d-c858-4ed1-9034-a8424f8a4c59)

When we test manually using Repeater with an incorrect username, the response is noticeably faster compared to when using a valid username and a significantly long password. This suggests that the server validates the username first and only proceeds to validate the password if the username is valid.
We proceed to check the difference in the response timing by performing the same attack, sending a large password (100 characters) using intruder:
![image](https://github.com/user-attachments/assets/6ebf0359-6729-4049-ab8d-2422d4bb6a8b)
We can see that the response with the username `amarillo` takes significantly longer than the other requests:
![image](https://github.com/user-attachments/assets/e64508d0-8ec5-4803-9dec-85bcbf1fca33)
We proceed to modify the payloads to perform a brute force attack with the passwords:
![image](https://github.com/user-attachments/assets/49bf4f60-2f68-4e3e-b0eb-8c50d49d0bc6)
![image](https://github.com/user-attachments/assets/da982241-62f1-435f-8730-f7587e3b29d6)

We proceed to log in and complete the lab:
![image](https://github.com/user-attachments/assets/4c88b9ba-d037-4366-958d-bbeecea53596)
