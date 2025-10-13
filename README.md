ChatNG
================

Authors:
* GramThanos (Athanasios Grammatopoulos)

Categories:
* Web security
* Cryptography
* Reverse Engineering

Overview
--------

Overview of Service:

The service is a web chat application, consisting of:
- the backend of a web chat application (in Python/Flask)
- a web server (Nginx) to serve the web application's frontend and proxy requests to the backend
- a tcp socket application (in Web Assembly) used to load chatting bot's on the service

### Flag Store 1

The first flag store is on the messages of the user to his/her self. (Alternativelly the flag store can change to file uploads on the same location).

### Flag Store 2

The second flag store is on the codes of the bots.

Vulnerabilities
---------------

Overview of the vulnerabilities:

- Flagstore 1
    - shared flask session key for all instances
        - forge flask session and login as user to see his/her notes
    - shared key for sharing feed of messages
        - forge share code to get list of messages
    - bit flip on chared codes to change target's user's username and generate valid code
        - brute force share code to get list of messages
    - vulnerable search
        - override search parameters to get messages of other users
- Flagstore 2
    - backdoor in mng
        - Send `AUTHEN botname n1s4_w4s_HEr3?` to authenticate
        - Send `GETCODE`
    - vulnerability in mng
        - Send `AUTHEN botname <first letter of token>` to authenticate
        - Send `GETCODE`
    - vulnerability in storing bot info
        - Create bot with JSON injection in token value to override bot name `token","name":"targetbotname`
        - Upload valid bot code with `debug` command
        - Execute `debug` command to load the code of another bot
    - vulnerability on proxy (path traversal)
        - /static../bots/botname.code


