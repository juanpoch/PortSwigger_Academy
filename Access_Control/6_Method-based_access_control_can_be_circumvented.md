# Lab: Method-based access control can be circumvented

This lab implements access controls based partly on the HTTP method of requests.
You can familiarize yourself with the admin panel by logging in using the credentials `administrator:admin`.

To solve the lab, log in using the credentials `wiener:peter` and exploit the flawed access controls to promote yourself to become an administrator.

---


# Report: Application Behavior Analysis and Exploitation

## Inspecting Normal Behavior

We began by inspecting the normal behavior of the application using the credentials `administrator:admin`:

![Normal behavior using admin credentials](https://github.com/user-attachments/assets/cbe7e749-0872-46e8-adfe-198b8b5de011)

## User Role Management

The application allows us to `upgrade` or `downgrade` any user:

![User management interface](https://github.com/user-attachments/assets/e02be972-e135-4e49-9825-e36f67422bc0)

We tested this functionality by upgrading Carlos's account:

![Upgrading Carlos's account](https://github.com/user-attachments/assets/7be1e87f-9a49-4325-a49a-79f75a4422c5)

## Logging Out and Testing Limitations

Next, we logged out of the admin account and signed in as the user `wiener`:

![Logging in as Wiener](https://github.com/user-attachments/assets/fc945ec2-02b5-41fd-ba6d-7caf3f2deff5)

We attempted to access the admin panel but were denied access:

![Access denied to admin panel](https://github.com/user-attachments/assets/01657973-c6b7-4767-a80b-20847de28ecb)

We also tried upgrading our account from the user interface but were unsuccessful:

![Upgrade attempt failed](https://github.com/user-attachments/assets/baa2ea71-9c8d-4d69-9d9b-ca20c2a416e0)

## Exploiting HTTP Verb Tampering

By leveraging an `HTTP verb tampering` attack, we successfully upgraded our account by changing the `POST` method to `GET`:

![Successful HTTP verb tampering attack](https://github.com/user-attachments/assets/89641d32-5786-4531-b8b5-7c073df50f45)

## Accessing the Admin Panel

Following the successful privilege escalation, we gained access to the `/admin` panel:

![Admin panel access](https://github.com/user-attachments/assets/a96d8916-c7e7-4a33-9a48-f9dea19e9140)



