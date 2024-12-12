# Lab: Multi-step process with no access control on one step

This lab has an admin panel with a flawed multi-step process for changing a user's role.
You can familiarize yourself with the admin panel by logging in using the credentials `administrator:admin`.

To solve the lab, log in using the credentials `wiener:peter` and exploit the flawed access controls to promote yourself to become an administrator.

---

## Upgrading an Account Using the Administrator Account

### Logging in as Administrator
1. We logged in as `administrator` and obtained the session cookie. The system redirected us to the administrator's home page:
   ![Administrator Login](https://github.com/user-attachments/assets/410f4d02-75e1-4230-8012-4cc30b245c01)  
   ![Administrator Home Page](https://github.com/user-attachments/assets/4577e131-4950-4267-ab43-8a450c45df35)

2. We accessed the `/admin` panel:
   ![Admin Panel](https://github.com/user-attachments/assets/294af614-56ed-45ce-8f14-b062822d9096)

3. From the panel, we initiated the role change process. The system prompted us with a confirmation message:
   ![Role Change Confirmation](https://github.com/user-attachments/assets/83474be2-7ad9-472b-86bd-a1250ca36fe1)

4. After confirming the change, the role was successfully updated:
   ![Role Change Successful](https://github.com/user-attachments/assets/1419b2a5-0176-45b6-9035-951e2cd357c8)

---

### Replicating the Process for the `wiener` User
1. We logged in as the `wiener` user, obtained the session cookie, and were redirected to the home page:
   ![Wiener Login](https://github.com/user-attachments/assets/6815b1ec-7112-4ac4-ae06-4064714309fb)  
   ![Wiener Home Page](https://github.com/user-attachments/assets/87823a93-304b-48a3-8827-b632516c267b)

2. Attempting to access the `/admin` panel was unsuccessful:
   ![Admin Panel Access Denied](https://github.com/user-attachments/assets/83c19adf-22c4-492d-8eb0-7ba6596ca128)

3. We bypassed the `/admin` panel step and attempted to change the role directly during the second step:
   ![Role Change Attempt - Step 2](https://github.com/user-attachments/assets/7ab76025-cdb8-41f9-b929-28715a47d21d)

4. Next, we skipped both the initial and second steps, directly modifying the role during the confirmation stage:
   ![Role Change Attempt - Confirmation Step](https://github.com/user-attachments/assets/5216d2e2-d01b-49a5-80f1-51dc3b0589c6)

5. Upon verifying the request's feasibility, we successfully changed the `wiener` user role and resolved the lab:
   ![Role Change Successful for Wiener](https://github.com/user-attachments/assets/107c195f-bc6c-4edb-82a7-8bd4fc4d7231)  
   ![Lab Resolved](https://github.com/user-attachments/assets/06d0309f-88fc-4a46-852c-a71e11829704)












