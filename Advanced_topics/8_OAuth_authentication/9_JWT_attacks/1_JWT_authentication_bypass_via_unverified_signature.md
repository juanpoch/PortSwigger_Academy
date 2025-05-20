# Lab: JWT authentication bypass via unverified signature

This lab uses a JWT-based mechanism for handling sessions. Due to implementation flaws, the server doesn't verify the signature of any JWTs that it receives.

To solve the lab, modify your session token to gain access to the admin panel at `/admin`, then delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

>Tip
>We recommend familiarizing yourself with [how to work with JWTs in Burp Suite](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/jwts) before attempting this lab.


---
