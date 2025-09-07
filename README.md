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

...

Vulnerabilities
---------------

    <!--
    Provide a high-level description of the vulnerabilities affecting each flag
    store. Include a proof-of-concept of the exploit, or - if this is not possible -
    a description of the attack flow. For each *vulnerability*, specify the intended
    difficulty level of the exploit, its *discoverability* by inspecting traffic
    dumps, etc., and *patchability*. Accepted values are *easy*, *medium*, *hard*.
    Vulnerabilities that are easy to exploit should be also easy to patch. On the
    other hand, it is fine to require more complex patches if the difficulty is also
    hard. It is also fine to keep the pathcability as easy if the discoverability is
    hard. Concerning discoverability, as a rule of thumb, there are 3 cases: *easy*,
    the exploit can be easily identified and reflected; *medium*, the exploit can be
    easily identified, but reflection is not trivial; *hard*, when identification
    and especially reflection are unlikely to be possible, e.g., if the connection
    is encrypted. We perfectly understand that precisely defining all possible
    vulnerabilities at this stage is difficult, but it's important to incorporate
    them during the design phase instead of adding some vulnerabilities at the end
    of the development
    -->

### Flag Store 1, Vuln 1

    <!--
    Short description of the vuln and how to exploit it
    -->

* Difficulty: easy
* Discoverability: hard
* Patchability: medium
* Categories: misc

### Flag Store 1, Vuln M

...

### Flag Store N, Vuln 1

...

### Flag Store N, Vuln K

...

Patches
-------

    <!--
    For each of the vulnerabilities reported in the previous section, outline a
    possible fix, can use diff files here to visualize changes but a text
    explanation is also required)
    -->

### Flag Store 1, Vuln 1

...

### Flag Store 1, Vuln M

...

### Flag Store N, Vuln 1

...

### Flag Store N, Vuln K

