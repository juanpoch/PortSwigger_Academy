# Lab: Web shell upload via extension blacklist bypass

This lab contains a vulnerable image upload function.
Certain file extensions are blacklisted, but this defense can be bypassed due to a fundamental flaw in the configuration of this blacklist.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`.

Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

`Hint`: You need to upload two different files to solve this lab. 

---

We tried to upload a simple php web-shelll but we noticed that extensions php are not allowed:
![image](https://github.com/user-attachments/assets/541d2f39-a7cc-4d1c-a6f4-b694779fc93a)

We tried to upload the same web-shell but using other lesser known, alternative file extensions as `.php5`:
![image](https://github.com/user-attachments/assets/a8f709b0-529a-4cb9-8986-cda21d92b2bb)

We noticed that we were not allowed to execute commands:
![image](https://github.com/user-attachments/assets/5b5ea732-dcc5-4eb7-8c04-f988b8946594)



