# Lab: Web shell upload via obfuscated file extension

This lab contains a vulnerable image upload function. 
Certain file extensions are blacklisted, but this defense can be bypassed using a classic obfuscation technique.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`. 
Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

---

We attempted to upload a simple php web shell but server responsed us with the "only JPG & PNG files are allowed":
![image](https://github.com/user-attachments/assets/0bcca2d1-a0d3-49a8-a8bf-b9d8449eed07)

We attempted to submit some obfuscated file names:
![image](https://github.com/user-attachments/assets/b5153e39-862c-47c2-973d-b5b355c6ba39)

![image](https://github.com/user-attachments/assets/73d0e90b-92dc-420a-850e-c594dfb4c600)

