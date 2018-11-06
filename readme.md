# Simple guardian Server

## Easy alternative to Fail2ban

Build to be **fast to deploy** *(deploying SG and making your server secure against OpenSSH, VSFTPD and Dovecot attacks takes under 6 seconds when using [Simple Guardian Server](https://github.com/esoadamo/simple-guardian-server))* and **easy to configure** *(uses JSON formatted dictionaries as profiles, no regex-skills needed).*

## How it works

You register to the server, then you create your device. The server will automatically generate a command (something like `wget -qO- "https://example.com/api/yourUsername/new_device/deviceID/auto" | sudo python3 -`), which you will only copy&paste to your Linux VPS's shell and after about 10 seconds of waiting, you are fully protected from attacks on OpenSSH, VSFPTD and Dovecot. Also the device is added to your register account and you can manage it remotely. The command you've just run downloaded and installed the [SG client](https://github.com/esoadamo/simple-guardian) for you.

If protected SSH, FTP and mail is not enough for your, then go to the **Hub**, where you can choose from profiles created by other users and install them on your server with just two clicks in your browser.

**All that without editing any configuration files or using regular expressions**. It's so simple.

## Features

- **easy installation of clients** under 10 seconds (take that, Fail2Ban)
- **easy configuration of clients** using web interface and statistics

![control panel](https://user-images.githubusercontent.com/15877754/48023225-72cb9780-e13d-11e8-95dd-307b3d6613ce.png)

- hub with application profiles shared by other users

![control panel](https://user-images.githubusercontent.com/15877754/48023222-719a6a80-e13d-11e8-93ca-c6d19ff7d553.png)

## Can I really secure my server against brute force attacks under one minute?

Yes! And you can see it for youself:

[![VIDEO: How to secure your VPS againts brute force attacks under one minute](https://i.imgur.com/ioQ4DBx.png)](https://youtu.be/jtzZVXeBUX4 "VIDEO: How to secure your VPS againts brute force attacks under one minute")