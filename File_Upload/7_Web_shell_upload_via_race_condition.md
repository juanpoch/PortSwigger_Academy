# Lab: Web shell upload via race condition

This lab contains a vulnerable image upload function. Although it performs robust validation on any files that are uploaded,
it is possible to bypass this validation entirely by exploiting a race condition in the way it processes them.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`. 
Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

---
