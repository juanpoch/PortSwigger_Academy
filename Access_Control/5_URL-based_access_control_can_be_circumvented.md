# Lab: URL-based access control can be circumvented

This website has an unauthenticated admin panel at `/admin`, but a front-end system has been configured to block external access to that path.
However, the back-end application is built on a framework that supports the `X-Original-URL` header.

To solve the lab, access the admin panel and delete the user `carlos`.

---

## Analysis of `/admin` Panel Access Attempt

### Initial Attempt
We attempted to access the `/admin` panel directly, but the application returned a plain response. This response appears to originate from the frontend:
![image](https://github.com/user-attachments/assets/998a4666-25af-4f00-a3f6-c7ade71392eb)

---

### Header Injection: `X-Original-URL`
Next, we tried injecting the `X-Original-URL` header into the request:
![image](https://github.com/user-attachments/assets/bc87fc1f-447c-4564-a25e-27892194b684)

The application returned a "not found" message, indicating that the `X-Original-URL` header is being processed.

The `X-Original-URL` header is a custom header that some servers use to indicate the original path of a request before it is modified or processed by a reverse proxy or load balancer. This allows applications to handle redirects, routing, or specific configurations based on the initial URL.

In this case, we are attempting to inject the `X-Original-URL` header to manipulate how the application interprets requests. By modifying this value, we aim to force access to restricted routes (such as `/admin`) or bypass access controls, leveraging the possibility that the server processes this header to make routing or authorization decisions.

---

### Header Injection to `/admin`
We then injected the `X-Original-URL` header to target the `/admin` panel:
![image](https://github.com/user-attachments/assets/08254ce7-065e-4894-814b-d104ecf253c8)

However, we observed that parameters could not be directly included in the `X-Original-URL` header:
![image](https://github.com/user-attachments/assets/c79ca6a2-7b2a-47e8-bff1-ddfa42364d87)

---

### Appending Parameters via GET Request
To bypass this restriction, we appended the parameters directly to the GET request:
![image](https://github.com/user-attachments/assets/f9aa0adc-8d40-4f5f-902a-cbfa744e26b6)

---

### Success: Lab Solved
Using this method, we successfully solved the lab:
![image](https://github.com/user-attachments/assets/9b2767e5-efb9-4e78-a28d-30706276139f)







