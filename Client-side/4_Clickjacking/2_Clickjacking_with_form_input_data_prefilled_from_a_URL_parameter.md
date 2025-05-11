# Lab: Clickjacking with form input data prefilled from a URL parameter

This lab extends the basic clickjacking example in `Lab: Basic clickjacking with CSRF token protection`. The goal of the lab is to change the email address of the user by prepopulating a form using a URL parameter and enticing the user to inadvertently click on an "Update email" button.

To solve the lab, craft some HTML that frames the account page and fools the user into updating their email address by clicking on a "Click me" decoy. The lab is solved when the email address is changed.

You can log in to your own account using the following credentials: `wiener:peter`

`Hint`: You cannot register an email address that is already taken by another user. If you change your own email address while testing your exploit, make sure you use a different email address for the final exploit you deliver to the victim.

![Practitioner](https://img.shields.io/badge/level-Apprentice-green) 

---
