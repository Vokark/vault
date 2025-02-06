# API Vault

## About this simple Vault

I am doing this project just because I like security and I see a lot of APIs without security and I protect them with a WAF, but I always say that it is better to protect your application and also use a WAF. WAF protection is not meant to hide the technical debt of developers.

This vault can be used to authenticate API ID and API KEYs from your applications (AKA: clients for this vault), any application you have can use a particular api_key and api_id, and level can be set.
This program was made with security in mind, it validates every parameter, name of the parameter, number of parameters and if they pass regular expression validation. So even though it is a long program, it only has a few endpoints.

I'm not a developer, so if you think something can be done better, feel free to share your ideas 😃

***ATENTION***: This project have no default users, clients or params, database come empty, you need to create your first API ID and KEY with the application for that.

## SQL File:

*** ***BE CAREFULL*** ***

- This SQL file will ***DROP YOUR DATABASE*** if a database called vault_ddbb already exists, it will create a database called "vault_ddbb" if you want to change the name, replace any part that has this:

```
From: vault_ddbb
To: your_db_name

```

- In the SQL file, you will see these lines towards the end:

```
DROP USER IF EXISTS change_user;
CREATE USER 'change_user' IDENTIFIED BY 'changeme';

GRANT ALL ON `vault_ddbb`.* TO 'change_user';
```

- Please go to ..... CHANGE IT!!. and use any username and password you like, or delete those lines and configure it by hand if you like.

## Python files:

1. [web-vault.py](web-vault.py): Is an API server that uses JSON to comunicate params to configure applications without using parameters directly in your program. This vault is secured, create SSL certificates as CA server and web certificate, also create a new certificate for each client you add and use public certificate to encrypt the parameter, in case someone can steal the database all values are illegibles. You will need private keys to read the values. If you are going to reinstall the server, remember to put all the files under your certificate directories.

1. [vaultmgmt.py](vaultmgmt.py): ***ATENTION*** delete this file after use, this file does not validate anything before creating users, this file is to create the first client to comunicate with the vault as there are no default users or params in this project, I always think of it as a production project even if I developed it just for fun.

1. [create-param.py](create-param.py): ***ATENTION*** delete this file after use, this file is the same as vaultmgmt.py for initial parameters you need to use vault, so avoid using it after first use.

1. [requirements.txt](requirements.txt): File to install all the Python libraries needed for this project.

1. [swagger.yaml](swagger.yaml): A file with the API structure. 


## USE:

Assuming you have backed up your database, change the user to anyone with rights to create databases on the server:

#### Mysql import:

***ATENTION*** again 😄, change this information if you need, sql file drop old database and tables, I'm not responsible if you don't check this information.

- Replace all data with old database name to any name you ***DON'T*** have created in your server ***BE CAREFUL***.

```
From: vault_ddbb
To: your_db_name

```

- In the SQL file, you will see these lines towards the end:


```
DROP USER IF EXISTS change_user;
CREATE USER 'change_user' IDENTIFIED BY 'changeme';

GRANT ALL ON `vault_ddbb`.* TO 'change_user';
```

- Import the database, change the database name, user name and password as described above, then you can restore the database 


```bash
$ mysql -uroot -p < vault.sql

```

#### Met the requirements:

Install the requirements from the requirements.txt file using pip. If you are using virtual environment, remember to enable it before doing this.

***If you use virtual environment***, activate with:
```bash
$ source /path/to/venv/bin/activate
$ pip install -r requirements.txt
```

***if not***, just use this:

```bash
$ pip install -r requirements.txt
```

#### Create first client (client is a client aplication not user).

Just use vaultmgmt.py to see how to do it, don't spaces os symbols, jus letters and numbers.

```bash
$ python3 vaultmgmt.py
Usage: python3 clientadd.py <add|generate_ssl> <client_name>

$ python3 vaultmgmt.py add testuser
Keys generated for client 1 and saved in /opt/vault/ssl/1
Client testuser added successfully.
API ID: sOFINGXT-YJhetmyK
API KEY: b1TL-uFTw8mBv-6834-ySmCU8Ai-BRDmsI9p

$
```

#### Create params

Use create-param.py to add a param:

```bash
$ python3 create-param.py
Usage: python3 create-param.py <client_name> <param_name> <param_value>

$ python3 create-param.py testuser param1 paramvalue
Parameter 'param1' created successfully for client 'testuser'.
```

#### Database params:

Now you can validate how param is displayed in database, it will use ~340 characters and with maximum 140 characters aproximately, so if you need more characters for your param, you need to alter database and duplicate chars for evety 140/150 chars (Now I don't remember the exact value but I think it was about 145 of plain text to 344 char in database and it will duplicate even if you use only 1 extra char. If you don't duplicate your field size, the data will be unreadable because it is not possible to reverse the operation with a missing part. That is why validation is so important in this project.

Database param with public key plus base64 to avoid odd characters:

```mysql
select nom_par_vch, val_par_vch from params;
+-------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| nom_par_vch | val_par_vch                                                                                                                                                                                                                                                                                                                                              |
+-------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| param1      | FcMsR0Au/GAgccc5fOv5uQMsMI2lLw0VCfoa5F5ExEZ/Hds5QzjcC/8Os5XXXis6JWvnsECMsj+Vz2ZHaVPx2T47VZzZDwiBuaexQiaLTQ7yZf+N4ooZSiiEioQ5Le/ErFQMD8A7Pb3crIrUSaDHZMXaopBvPzk/FsNI9JrxsCuCJzhFl61ETGI8c+xGI1Cy3jCJ9dt31Ol9Y+6wZFNuCIAXl7RBgUsl3q0w+BwyUpKAkiez2MeyWVED03bQO4t39v5E7pFkAMKVPG2Yp7XZHa9kotackJaCSwmeYOb9njxXtLecVMEW9r+HVvOB30u45ZimB0pSD93xHZvkHQk7zg== |
+-------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
1 row in set (0.000 sec)

```


## Docker:

You can use this app in a docker environment if you wish and can configure variables as global or put the value at hand (not recomended). 
