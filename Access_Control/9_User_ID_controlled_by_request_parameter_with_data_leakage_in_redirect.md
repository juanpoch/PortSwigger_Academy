# Lab: User ID controlled by request parameter with data leakage in redirect

This lab contains an access control vulnerability where sensitive information is leaked in the body of a redirect response.

To solve the lab, obtain the API key for the user `carlos` and submit it as the solution.

You can log in to your own account using the following credentials: `wiener:peter`


---

# Write-Up: Response Body Data Leak Exploitation

## Logging in as `wiener` and Inspecting User-Controlled Parameters
We start by logging in as `wiener` and inspecting the processed requests to identify user-controlled parameters:  
![Request Inspection](https://github.com/user-attachments/assets/024ff4aa-a1b1-4e3a-ba40-842930d93bd6)  

We notice the `id` parameter in one of the requests:  
![Parameter Inspection](https://github.com/user-attachments/assets/d04ca551-13b2-4d09-91e6-45a6916b5340)  

## Testing the `id` Parameter in Repeater
We send the request to the `Repeater` and attempt to modify the value of the `id` parameter. However, we observe that it redirects us to the login page:  
![Redirect to Login](https://github.com/user-attachments/assets/b888e812-04f9-46c3-b47c-997cd8ec2a1d)

## Exploiting the Data Leak in the Response Body
Despite the redirection, the response body contains the source code of `carlos`' homepage, exposing its content and revealing `carlos`' API Key:  
![API Key Leak](https://github.com/user-attachments/assets/7a06907f-a628-47b7-a600-cc3da4686318)

## Solving the Lab
We submit the leaked API Key and solve the lab:  
![Lab Solved](https://github.com/user-attachments/assets/b0d4e1e5-d107-4b41-9a67-8e7f9ee87fb9)

