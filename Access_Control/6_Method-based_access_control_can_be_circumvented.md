# Lab: Method-based access control can be circumvented

This lab implements access controls based partly on the HTTP method of requests.
You can familiarize yourself with the admin panel by logging in using the credentials `administrator:admin`.

To solve the lab, log in using the credentials `wiener:peter` and exploit the flawed access controls to promote yourself to become an administrator.

---


We inspect the normal behavior of the application by using `administrator:admin` credentials:
![image](https://github.com/user-attachments/assets/cbe7e749-0872-46e8-adfe-198b8b5de011)

Then we can `upgrade` or `downgrade` any user:
![image](https://github.com/user-attachments/assets/e02be972-e135-4e49-9825-e36f67422bc0)

We test this feature by upgrading carlos's account:
![image](https://github.com/user-attachments/assets/7be1e87f-9a49-4325-a49a-79f75a4422c5)

Then we logged out and sign in as wiener:
![image](https://github.com/user-attachments/assets/fc945ec2-02b5-41fd-ba6d-7caf3f2deff5)

We tried to acces admin panel without success:
