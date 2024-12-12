# Lab: User ID controlled by request parameter, with unpredictable user IDs

This lab has a horizontal privilege escalation vulnerability on the user account page, but identifies users with `GUIDs`.

To solve the lab, find the GUID for carlos, then submit his API key as the solution.

You can log in to your own account using the following credentials: `wiener:peter`

---

# Write-Up: GUID-Based IDOR Exploitation

## Logging in as `wiener` and Analyzing Requests
We begin by logging in as the user `wiener` and inspecting the site. We carefully review all requests that include parameters:  
![Requests Inspection](https://github.com/user-attachments/assets/34f2b7e5-c761-4ae1-bbff-f1389258acda)  

One such request contains the `id` parameter:  
![Parameter Inspection](https://github.com/user-attachments/assets/c4f1ae69-3256-408b-a71e-f1198ba7f393)

Although we observe the `id` parameter, it does not follow a predictable pattern.

## Investigating the Comments Section
Continuing the inspection, we navigate to the comments section and notice a post by `carlos`:  
![Carlos's Comment](https://github.com/user-attachments/assets/1cb1da9a-8e9f-4eeb-b363-a0efe5bce6cb)

## Extracting the GUID
By analyzing the source code of the page, we find the GUID (Globally Unique Identifier) associated with `carlos`:  
![GUID Extraction](https://github.com/user-attachments/assets/59f26bbf-74b6-4cc9-9e88-a9604f8d2a0c)

## Exploiting the IDOR and Retrieving the API Key
We send a `GET` request to `/my-account` using the `id` parameter corresponding to `carlos`' GUID. As a result, we successfully retrieve `carlos`' API Key:  
![API Key Retrieved](https://github.com/user-attachments/assets/cb4aa393-6a5d-46e7-b183-1513d6a2d866)

## Solving the Lab
Finally, we use the API Key to complete the lab:  
![Lab Solved](https://github.com/user-attachments/assets/fef99e91-c140-4866-9928-4ea41dda4c76)


