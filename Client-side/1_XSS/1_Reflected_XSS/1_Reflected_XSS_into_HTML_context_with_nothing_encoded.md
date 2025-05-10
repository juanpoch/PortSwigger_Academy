# Lab: Reflected XSS into HTML context with nothing encoded

This lab contains a simple reflected cross-site scripting vulnerability in the search functionality.

To solve the lab, perform a cross-site scripting attack that calls the `alert` function. 

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---

# XSS Vulnerability Demonstration

We have a form to input a search query. Initially, we input a simple payload:
![image](https://github.com/user-attachments/assets/42df6a4a-94c0-409d-bf47-f8a05368c333)

When we input `HTML` tags, we observe that they are injected into the source code and executed: 
![image](https://github.com/user-attachments/assets/a058951c-6850-420f-9963-08afaac768bd)

Next, we enter the following payload:  
```javascript
<script>alert('XSS')</script>
```
![image](https://github.com/user-attachments/assets/306c086b-3f2e-4582-bcc9-2a7d66c38cfe)
![image](https://github.com/user-attachments/assets/3207a728-966a-4b00-853d-4c68932b6e29)

