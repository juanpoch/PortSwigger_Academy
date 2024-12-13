# Lab: Web shell upload via extension blacklist bypass

This lab contains a vulnerable image upload function.
Certain file extensions are blacklisted, but this defense can be bypassed due to a fundamental flaw in the configuration of his blacklist.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`.

Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

`Hint`: You need to upload two different files to solve this lab. 

---

We attempted to upload a simple PHP web shell, but observed that files with the `.php` extension are not allowed. During this process, the server leaked its `Apache` version:  
![image](https://github.com/user-attachments/assets/24658572-1585-4896-9cc8-0edcacc88c78)

Subsequently, we tried uploading the same web shell using alternative, lesser-known file extensions such as `.php5`:  
![image](https://github.com/user-attachments/assets/a8f709b0-529a-4cb9-8986-cda21d92b2bb)

Although the file upload was successful, we noticed that we were unable to execute commands:  
![image](https://github.com/user-attachments/assets/5b5ea732-dcc5-4eb7-8c04-f988b8946594)


- For Apache servers, we could upload the `.htaccess` configuration file:
  ```text
  LoadModule php_module /usr/lib/apache2/modules/libphp.so
    AddType application/x-httpd-php .php
  ```
 This file modifies the server's configuration to treat files with the `.any` extension as PHP scripts.
- For IIS servers, we could replace the `web.config` configuration file:
  ```text
  <staticContent>
    <mimeMap fileExtension=".json" mimeType="application/json" />
    </staticContent>
  ```

Since the server is running Apache, we attempted to upload the `.htaccess` configuration file with the following content:  
![image](https://github.com/user-attachments/assets/3e57a89e-acc8-451c-adf7-42dd59fa8480)

This configuration maps the arbitrary extension `.any` to the executable MIME type `application/x-httpd-php`. Because the server uses the `mod_php` module, it automatically knows how to handle this.

Next, we uploaded the web shell with the `.any` extension:  
![image](https://github.com/user-attachments/assets/e955caf2-2d91-4b22-b81e-cc23fc6994f6)

After successfully executing the web shell, we retrieved the code and solved the lab:  
![image](https://github.com/user-attachments/assets/c6eef6e7-d1f4-4f47-bd59-d65088790733)  
![image](https://github.com/user-attachments/assets/2ec5c20b-8fe6-4e1f-937f-2ca9f18ce4e5)






