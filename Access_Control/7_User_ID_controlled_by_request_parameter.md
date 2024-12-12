# Lab: User ID controlled by request parameter

This lab has a horizontal privilege escalation vulnerability on the user account page.

To solve the lab, obtain the API key for the user `carlos` and submit it as the solution.

You can log in to your own account using the following credentials: `wiener:peter`


---

# Write-Up: Simple IDOR Exploitation

## Logging in as `wiener`
We start by logging into the application as the user `wiener`:  
![Login Screen](https://github.com/user-attachments/assets/56f04955-5b2b-423d-a160-e6f030db1d33)

## Redirect to `wiener`'s Home Page
Upon logging in, we are redirected to `wiener`'s home page:  
![Home Page Redirect](https://github.com/user-attachments/assets/6c9a4a86-fe69-4625-b95a-7a889347a664)

## Identifying the `id` Parameter
On the home page, we observe a parameter named `id` that we control. This suggests a potential IDOR (Insecure Direct Object Reference) vulnerability. We proceed by sending the request to the Burp Suite Repeater tool and modifying the value of the `id` parameter:  
![Testing IDOR](https://github.com/user-attachments/assets/e85d1f71-c8fa-43fc-9a05-a3d4f04556e1)

## Exploiting the IDOR and Retrieving the API Key
By altering the `id` parameter, we successfully exploit the vulnerability and retrieve an `API Key`. We then submit the key and solve the lab:  
![API Key Retrieved](https://github.com/user-attachments/assets/06d46777-afd6-443d-ae4e-0e833a8e1df5)




