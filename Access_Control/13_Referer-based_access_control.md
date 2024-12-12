# Lab: Referer-based access control

This lab controls access to certain admin functionality based on the Referer header. 
You can familiarize yourself with the admin panel by logging in using the credentials `administrator:admin`.

To solve the lab, log in using the credentials `wiener:peter` and exploit the flawed access controls to promote yourself to become an administrator.

---


## Normal Flow for Account Upgrade Using the Administrator Account

### Logging in as Administrator
1. We logged in as the `administrator` account and received the session cookie:
   ![Administrator Login Cookie](https://github.com/user-attachments/assets/0bb8551f-a306-4b2f-a9a4-8e1cfb034ba0)

2. Accessed the admin panel:
   ![Admin Panel](https://github.com/user-attachments/assets/21d0f090-170d-460f-b210-5ae39d519c54)

3. Changed the role of the user `carlos` to a higher privilege:
   ![Change Role of Carlos](https://github.com/user-attachments/assets/fcd4868f-ced6-4725-b555-327f85c5b070)

---

## Attempting to Replicate the Flow with the `wiener` User

### Logging in as `wiener`
1. We logged in as the `wiener` user and received the session cookie:
   ![Wiener Login Cookie](https://github.com/user-attachments/assets/9351da1a-f53e-4797-a9d8-d3f1d5c51cdd)

### Attempting to Change Role Without Referer Header
2. Tried to change the user role directly, omitting the `Referer` header:
   ![Role Change Attempt Without Referer](https://github.com/user-attachments/assets/8f1708e3-5b38-465b-93b9-07ab59c801ee)

3. Observed that the server enforces access control by validating the `Referer` header:
   - Without the `Referer` header:
     ![Referer Validation - Blocked](https://github.com/user-attachments/assets/d72da4c8-a6c9-4e54-843d-15cbbe72e035)
   - After adding the `Referer` header:
     ![Referer Validation - Allowed](https://github.com/user-attachments/assets/a8942569-0c54-47b5-b723-70970ca1ab67)

---

### Observations
The server's access control mechanism relies on the presence of the `Referer` header, which is a weak and bypassable security measure. Manipulating this header allows unauthorized users to circumvent restrictions and perform privileged actions, such as role upgrades.

---
Let me know if this summary needs any adjustments or further details.








