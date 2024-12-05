# Lab: Brute-forcing a stay-logged-in cookie

This lab allows users to stay logged in even after they close their browser session. The cookie used to provide this functionality is vulnerable to brute-forcing.

To solve the lab, brute-force Carlos's cookie to gain access to his `My account` page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`
- Wordlists: Candidate passwords
---

# Session Cookie Analysis and Attack Execution

## 1. Keep Me Logged In Option
- When logging in and selecting the "Keep me logged in" option, the processing appears as follows:  
  ![image](https://github.com/user-attachments/assets/26704adc-199f-4482-86e1-a621abeb964f)

---

## 2. Decoding the Cookie
- We know the cookie is encoded in `base64`. After decoding, we obtain the following structure:  
  `wiener:<hash md5>`  

- The value `51dc30ddc473d43a6011e9ebba6ca770` contains 32 hexadecimal characters, suggesting it is an `MD5 hash`:  
  ![image](https://github.com/user-attachments/assets/9062361d-8f9b-4183-8b59-c7c0fb02bbe8)

---

## 3. Sending the Request to Intruder
- We send the request to the Intruder tool, ensuring the session cookie is empty.  
- Then, we add `payload processing` rules as follows:
  1. Compute the MD5 hash of the password.
  2. Add the prefix `carlos` to the hash.
  3. Encode the resulting string in `base64`:  
  ![image](https://github.com/user-attachments/assets/3327d4f6-8126-46ce-afb7-ad0fbd66084a)

---

## 4. Executing the Attack
- Finally, we execute the attack to identify valid payloads:  
  ![image](https://github.com/user-attachments/assets/4b9e1439-eab0-4804-9174-5920037396d3)  
  ![image](https://github.com/user-attachments/assets/417e5ff9-b40f-4f22-956c-a227a9c08275)



