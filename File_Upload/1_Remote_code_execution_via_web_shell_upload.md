# Lab: Remote code execution via web shell upload

This lab contains a vulnerable image upload function. It doesn't perform any validation on the files users upload before storing them on the server's filesystem.

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`.
Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

---

## Exploiting File Upload Functionality for Remote Code Execution (RCE)

### Initial Discovery
1. Upon logging in as the `wiener` user, we discovered a feature on the home page to upload an avatar image:
   ![Avatar Upload Feature](https://github.com/user-attachments/assets/443c2f4a-de2c-4913-a004-1e757502520c)
   
2. The uploaded image was stored in the `/files/avatars/` directory, as observed in the page source code.

---

### Uploading a Test File
1. We intercepted the request for uploading the image using Burp Suite and sent it to the Repeater for further analysis:
   ![Upload Request in Repeater](https://github.com/user-attachments/assets/e64e72d4-73a5-4317-97eb-5c53079763f8)

2. After analyzing the request, we attempted to upload a malicious file containing a PHP one-liner:
   ```php
   <?php echo file_get_contents('/home/carlos/secret'); ?>
   ```
   We could also attempt to use others like this:
   ```php
   <?php system($_GET['cmd']); ?>
   ```
   ![image](https://github.com/user-attachments/assets/e8fa4c9e-2335-4f61-a057-79259093c45b)


   ## **Accessing the Malicious File**
 **Navigating to the Uploaded File:**  
   After successfully uploading the PHP file containing the malicious one-liner, we accessed it directly via the browser using the file path provided by the server:  
   ![Accessing the Malicious File](https://github.com/user-attachments/assets/d8a0d66a-ada2-46c7-bcca-e5d32e2390b5)

---

## **Lab Resolution** 
We submitted the secret using the button provided in the lab banner:
   ![Lab Resolution](https://github.com/user-attachments/assets/c1901f90-ebf0-49e4-85fd-b9dfcede187f)

   
We could also use:
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```
![image](https://github.com/user-attachments/assets/742e29f0-9fed-47a8-8dc9-f2597a83d6b6)
![image](https://github.com/user-attachments/assets/c2f45d2d-cce5-4b0c-87f4-a641d4245295)




