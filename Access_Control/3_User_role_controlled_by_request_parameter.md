# Lab: User role controlled by request parameter

This lab has an admin panel at `/admin`, which identifies administrators using a forgeable cookie.

Solve the lab by accessing the admin panel and using it to delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter` 
---

We logged in using our credentials and attempted to access the `/admin` panel:  
![image](https://github.com/user-attachments/assets/a67a3418-767a-47f8-a920-5dc86060b0ad)  

We noticed the `admin` parameter in the `cookie`. We sent the request to the `repeater` for further testing:  
![image](https://github.com/user-attachments/assets/cb1dcefe-b8c7-4d56-9660-9e1f31d429af)  

After modifying the request:  
![image](https://github.com/user-attachments/assets/fbe230f4-80f9-46ac-89df-3b0a326594ef)  

We successfully deleted the `carlos` user and solved the lab:  
![image](https://github.com/user-attachments/assets/2ad839f0-e656-4779-8ff5-e9773f96c3a9)  
![image](https://github.com/user-attachments/assets/2c161242-8eb1-4f54-9e00-260bbd6a352d)  




