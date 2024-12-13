# Lab: Web shell upload via path traversal

This lab contains a vulnerable image upload function.
The server is configured to prevent execution of user-supplied files, but this restriction can be bypassed by exploiting a secondary vulnerability.

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`.
Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

---

We attempted to upload a web shell:  
![image](https://github.com/user-attachments/assets/a702a046-ff51-4064-b92f-e09e74838ddc)

Although we successfully uploaded the malicious file, the server did not execute the script when we accessed it:  
![image](https://github.com/user-attachments/assets/a10ad05c-11ab-4429-9d20-8f4a87358734)

This behavior suggests that the server is likely configured to prevent the execution of uploaded files, possibly by enforcing strict permissions or file handling rules.

We then tried a path traversal attack on the `filename`:  
![image](https://github.com/user-attachments/assets/5f1566cf-df9e-4b91-b0f3-109e705545cc)  
The response indicated that the server was stripping the directory traversal sequence from the filename.

Next, we submitted the same request but with the "/" character `url-encoded`:  
![image](https://github.com/user-attachments/assets/3799c2be-3d00-41d4-82f5-81cadf26a49c)

This time, we successfully accessed the uploaded file:  
![image](https://github.com/user-attachments/assets/ec42a65d-cccd-49ae-a3ed-f521c66b003d)

Finally, we submitted the code and successfully solved the lab:  
![image](https://github.com/user-attachments/assets/c3d0fa8d-aa50-425c-96aa-6c36c21bb52e)








