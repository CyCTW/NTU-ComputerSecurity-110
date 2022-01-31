# ProfileCard exploit step by step
## 1. Host the website
By using apache2, first link this repository to `/var/www/html`

```sudo ln -s . /var/www/html```

Host the website

```ngrok http 80```

## 2. Trigger the bot and wait for result
Go to the page to compute PoW and paste the ngrok URL to trigger the bot.

Then, wait for the request to ngrok and see the flag.