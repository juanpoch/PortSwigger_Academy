# Lab: Web shell upload via race condition

This lab contains a vulnerable image upload function. Although it performs robust validation on any files that are uploaded,
it is possible to bypass this validation entirely by exploiting a race condition in the way it processes them.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`. 
Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

`Hint`:
The vulnerable code that introduces this race condition is as follows:
```php
<?php
$target_dir = "avatars/";
$target_file = $target_dir . $_FILES["avatar"]["name"];

// temporary move
move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file);

if (checkViruses($target_file) && checkFileType($target_file)) {
    echo "The file ". htmlspecialchars( $target_file). " has been uploaded.";
} else {
    unlink($target_file);
    echo "Sorry, there was an error uploading your file.";
    http_response_code(403);
}

function checkViruses($fileName) {
    // checking for viruses
    ...
}

function checkFileType($fileName) {
    $imageFileType = strtolower(pathinfo($fileName,PATHINFO_EXTENSION));
    if($imageFileType != "jpg" && $imageFileType != "png") {
        echo "Sorry, only JPG & PNG files are allowed\n";
        return false;
    } else {
        return true;
    }
}
?>
```
---


## Exploiting the Race Condition

We started by attempting to upload a simple PHP web shell to the vulnerable server. The web shell was designed to allow us to execute arbitrary commands, but the server responded with a validation error, stating that only JPG and PNG files are allowed:

![image](https://github.com/user-attachments/assets/17def7d4-6759-4383-a0b3-a365ed765868)

### Race Condition Attack Strategy

To exploit the race condition in the file upload process, we crafted a sequence of requests where we:

1. **Uploaded the PHP web shell** multiple times concurrently.
2. Simultaneously sent requests to **execute the uploaded file** before the server completed its validation process.

This strategy was tested in the following configurations:
- **Single connection:** Sequentially sent the upload and execution requests over the same connection.
- **Separate connections:** Used different connections for uploading the web shell and executing it.
- **Parallel connections:** Sent multiple upload and execution requests simultaneously to increase the likelihood of a timing mismatch.

Eventually, we managed to access the uploaded PHP file before the server removed it during the validation step:

![image](https://github.com/user-attachments/assets/064a1ced-13d7-4a21-bd91-1a281654dcdc)

### Lab Completion

Using the uploaded web shell, we retrieved the contents of the `/home/carlos/secret` file and successfully submitted the secret, solving the lab:

![image](https://github.com/user-attachments/assets/cdcd5afa-804f-4ca4-ba38-11c07703e28a)

