# Lab: 2FA bypass using a brute-force attack

This lab's two-factor authentication is vulnerable to brute-forcing. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, brute-force the 2FA code and access Carlos's account page.

- Victim's credentials: `carlos:montoya`

**Note**: As the verification code will reset while you're running your attack, you may need to repeat this attack several times before you succeed. This is because the new code may be a number that your current Intruder attack has already attempted.  

Hint: You will need to use Burp macros in conjunction with Burp Intruder to solve this lab. For more information about macros, please refer to the Burp Suite documentation. Users proficient in Python might prefer to use the Turbo Intruder extension, which is available from the BApp store.


We attempted to log in with Carlos' credentials twice, but we noticed that the server logs us out after the second attempt:
![image](https://github.com/user-attachments/assets/6b89c208-1f17-413f-af91-84f5cc89e9c4)
![image](https://github.com/user-attachments/assets/43245b88-a92b-4dfc-b722-c3b903555825)

Then send the `POST` request to send the token:
![image](https://github.com/user-attachments/assets/274a4ad9-4038-4861-9ebe-88699e2d07d0)


# Login Flow

- Click on `My Account`:
![image](https://github.com/user-attachments/assets/be059c4a-d0f0-4320-97a3-c6201dd42341)
![image](https://github.com/user-attachments/assets/07b64f24-a794-46fa-9a82-c395d38a69a7)


- Attempt to log in, then we received a sesion token:
![image](https://github.com/user-attachments/assets/66a4f27c-1b64-47a3-b51d-d32387337a3a)


- Then we send a request to get the 2fa code panel by using the token previously received:
![image](https://github.com/user-attachments/assets/69ac5ca3-12c1-446d-8c83-494c85f787ec)



## Using macros to brute-force token:

We select the main requests needed to perform the attack following the flow:
![image](https://github.com/user-attachments/assets/ca13170c-127a-4063-ae0e-00b01b936c24)
Test the Macro:
![image](https://github.com/user-attachments/assets/22647ca9-a677-4aa9-833c-39089f76d0f0)
On `Scope` click on `Include all URLs`:
![image](https://github.com/user-attachments/assets/6e257995-515b-4797-a4fe-faf39740d321)

Send the `POST /login2` endpoint to the Intruder and make a bruteforce attack using the macros:

- Payload configuration:
![image](https://github.com/user-attachments/assets/d42c3a84-b8c3-4ac8-aea4-360bb208d987)

- Don't forget to set the `Maximum concurrent requests` to 1:
![image](https://github.com/user-attachments/assets/2f98052c-6a85-4f4a-96dc-f3bdb3a002a3)


- Then attack and we will get the cookie session:
![image](https://github.com/user-attachments/assets/03ce31cb-b6d0-4cbc-a98d-5371e0dc7702)
![image](https://github.com/user-attachments/assets/48c5bcc5-f91a-4c2c-9be9-27a036feb92b)


