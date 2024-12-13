# Lab: Web shell upload via obfuscated file extension

This lab contains a vulnerable image upload function. 
Certain file extensions are blacklisted, but this defense can be bypassed using a classic obfuscation technique.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`. 
Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

---

## Web Shell Upload Exploit Process

1. **Initial Attempt**:
   We initially tried to upload a simple PHP web shell, but the server responded with a restriction message, allowing only JPG and PNG files:
   
   ![image](https://github.com/user-attachments/assets/0bcca2d1-a0d3-49a8-a8bf-b9d8449eed07)

2. **Obfuscated Filenames**:
   We then attempted to bypass this restriction by submitting files with obfuscated filenames:
   
   ![image](https://github.com/user-attachments/assets/b5153e39-862c-47c2-973d-b5b355c6ba39)
   
   ![image](https://github.com/user-attachments/assets/73d0e90b-92dc-420a-850e-c594dfb4c600)

3. **No Command Execution**:
   Unfortunately, the last web shell we tried did not provide command execution capabilities:
   
   ![image](https://github.com/user-attachments/assets/26cc6e9e-8d75-4062-ae63-e81fd8c0e66b)

4. **Null Byte Injection**:
   We attempted another method by changing the `filename` parameter to include a URL-encoded null byte (`%00`), followed by the `.jpg` extension:
   
   ![image](https://github.com/user-attachments/assets/9fbe95b8-cea6-4485-be70-20985a2b0737)

5. **Successful Code Execution**:
   This approach allowed us to execute the code and successfully solve the lab challenge:
   
   ![image](https://github.com/user-attachments/assets/42d299f9-8663-4158-9115-0e49f01b744d)
   
   ![image](https://github.com/user-attachments/assets/23f5b45c-da86-4744-8f03-94356d344fd3)





