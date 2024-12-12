# Lab: Web shell upload via Content-Type restriction bypass

This lab contains a vulnerable image upload function. It attempts to prevent users from uploading unexpected file types,
but relies on checking user-controllable input to verify this.

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`.
Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

---

For this lab, we used a simple `php one-liner`:
```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```

We logged in with our own credentials and uploaded an image using the provided feature. By inspecting the source code, we identified the location where the uploaded file was stored:  
![image](https://github.com/user-attachments/assets/6b53d155-da91-4fa6-bb52-a491291cd03e)

Next, we attempted to upload a malicious file named `test.php` to the server:  
![image](https://github.com/user-attachments/assets/c82aa8db-3eb2-440b-bc6c-39a929c9b1b3)

We successfully used the uploaded file to read the content of `/home/carlos/secret`:  
![image](https://github.com/user-attachments/assets/9e13e878-0cec-42e6-a0ed-0cce03fbb451)

Finally, we submitted the file content to solve the lab:  
![image](https://github.com/user-attachments/assets/36e9a868-f85a-4fee-8a23-2c41cfe9cb80)





