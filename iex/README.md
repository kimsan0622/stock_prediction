# IEX data

## Download files

Download packet capture files if you want. Please refer [**this**](./data/README.md).

## IEX packet preprocessing

We use MongoDB for querying IEX messages because the amount of message data is too large.

## Create MongoDB database

In this project, we will use the MongoDB Docker Container to serve it. You can use custom platform for running MongoDB service such as VirtualBox, remote server, local machine.

1. install docker if you didn't install it yet.

2. pull mongodb docker and run it as non-authorized mode.

```bash
    # pull the mongo db image
    docker pull mongo
    # run a mongo db container as non-authorized mode.
    # e.g.) docker run -d --name iex_mongodb -p 27017:27017 -v /home/san/nfs/iex_mongodb:/data/db -d mongo
    docker run -d --name {container_name} -p {host port}:27017 -v {path to host volume}:/data/db -d mongo
```

3. create admin account for managing database.

```bash
    # run the bash of the container
    # e.g.) docker exec -it iex_mongodb /bin/bash
    docker exec -it {container_name} /bin/bash
    
    # run mongo on the shell of the container
    mongo
    # switch to 'admin' database
    use admin
    # create 'admin' user
    # e.g.) db.createUser({user:"admin",pwd:"admin1234",roles:[{role:"userAdminAnyDatabase",db:"admin"}]})
    db.createUser({user:"admin",pwd:"{password of admin account}",roles:[{role:"userAdminAnyDatabase",db:"admin"}]})
```

4. run container with authorized mode and create database and user.

```bash
    # run container with authorized mode
    docker run -d --name iex_mongo -p 27017:27017 -v /home/san/nfs/stock_data/mongodb:/data/db -d mongo -auth

    # enter the container
    docker exec -it iex_mongo /bin/bash

    # access mongodb as admin user
    mongo -u "admin" -p "admin" -authenticationDatabase "admin"

    # create database and a client who has permission of that database.
    use iex_data
    db.createUser({user:"iex_client", pwd:"1234", roles:["dbAdmin", "readWrite"]})
```