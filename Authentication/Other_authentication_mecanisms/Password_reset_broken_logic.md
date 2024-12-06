# Lab: Password reset broken logic

This lab's password reset functionality is vulnerable. To solve the lab, reset Carlos's password then log in and access his "My account" page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`
---

# Password Reset Flow:

### Click on `Forgot password?`:
![image](https://github.com/user-attachments/assets/7e8ecbb4-617e-4182-a4e6-874009754acc)

---

### Fill out the form with our username:
![image](https://github.com/user-attachments/assets/332efff2-0180-4528-a40e-705964305cdb)

---

### Go to our email:
![image](https://github.com/user-attachments/assets/660af633-2649-42e2-9a6b-1791413bbe49)

---

### Access the password reset URL:
![image](https://github.com/user-attachments/assets/dc8b67d3-c030-40c7-82c4-dba1abcb697f)

---

### Reset the password:
![image](https://github.com/user-attachments/assets/8a48b6a5-5cb5-45d7-9ca9-b7b551126bc5)

---

### We observe that the reset token could be reused. We attempt to reset the password for `carlos` by sending the last request to the repeater:
![image](https://github.com/user-attachments/assets/de42f9a9-8d71-4791-8458-998baf255f29)

---

### Log in as carlos and solve the lab:
![image](https://github.com/user-attachments/assets/151c616c-1d29-41ff-8a58-c0714f0978d8)
