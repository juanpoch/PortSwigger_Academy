# Lab: 2FA broken logic

This lab's two-factor authentication is vulnerable due to its flawed logic. To solve the lab, access Carlos's account page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`
You also have access to the email server to receive your 2FA verification code.

Hint: Carlos will not attempt to log in to the website himself.


# Application Flow Description Using Credentials

## Normal Application Flow:

1. **Login with valid credentials**:  
   ![image](https://github.com/user-attachments/assets/64f381fa-5fc7-48ff-8b00-4ba03740cfda)  
   This endpoint provides a cookie to perform subsequent requests.

2. **Request the resource that requires 2FA using the provided cookie**:  
   ![image](https://github.com/user-attachments/assets/2c5f499b-9ea8-411d-9864-aeae13b42afa)

3. **Click on "Email client"**:  
   ![image](https://github.com/user-attachments/assets/85d1ea4c-91ae-4ae1-995a-8ad474f77157)

4. **Enter the 2FA code and receive a new cookie**:  
   ![image](https://github.com/user-attachments/assets/8ea23f39-d282-4c5a-b3a3-62f613921456)

5. **Access the next endpoint, where we provide the new cookie and successfully log in**:  
   ![image](https://github.com/user-attachments/assets/5533b462-fa84-416e-87bc-f4b6eb7bd634)

## Replicating the Flow with Another User (Carlos):

1. **Log out and try to replicate the same flow for the user "carlos" using the initial credentials of "wiener"**:  
   ![image](https://github.com/user-attachments/assets/69e60da7-8796-48af-96d6-1639defb6950)  
   ![image](https://github.com/user-attachments/assets/ef67c05b-d028-4325-b353-2851b5dc1e85)

2. **The email address remains that of "wiener"**:  
   ![image](https://github.com/user-attachments/assets/4e3f48c5-4129-439f-9aae-4ad9886f4666)

3. **Set up Burp Intruder to perform a Sniper Attack on the `mfa-code` parameter**:  
   - Filter by `302 Found` or `Incorrect security code` in the `Settings` under `Grep - Extract`.  
   ![image](https://github.com/user-attachments/assets/b2f290cf-548e-48aa-8850-64e9d2d8bff6)

4. **Once the attack is executed, we observe a `302 Found`. Enter the received cookie to access Carlos's dashboard**:  
   ![image](https://github.com/user-attachments/assets/94d7763b-6d22-4159-867d-f45bc21adbd2)  
   ![image](https://github.com/user-attachments/assets/3c85fc9f-2bc2-4376-b8ab-7acb5eb52d95)









