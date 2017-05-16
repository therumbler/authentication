# Authentication

This is a crude proof of concept, attempting to use accepted crypto standards for user account creation/verification.

Please don't use this for anything serious.


## Setup

* Copy `config.conf.template` to `config.conf`

    `mv config.conf.template config.conf`

* fill in the values in `config.conf`

    ```
    [email]
    host : 
    port : 
    username : 
    password : 

    [server]
    hostname : localhost
    port : 5000

    [app]
    secret_key : 
    ```

* Install the requirements (currently only `Flask`) with pip

    pip install -r requirements.txt



