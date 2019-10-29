# IEX data Preprocessing module
## iex packet module

iex_packet module has two types of class. one is IEX_Packet class, another is IEX_Message class.
IEX_Packet class parse a IEX-TP packet which follows the IEX Transport Protocol. (You can find the specification of IEX-TP v1 in [**here**](https://iextrading.com/trading/market-data/#specifications))
Therefore, you can parser the IEX packet from a packet capture file using this class and packet capture parser.
I recommend you to use the 'scapy' module for parsing a packet capture file (This kind of files usually get **.pcap** as an extension.).
There are 13 subclasses (S, D, H, O, P, E, 8, 5, Q, T, X, B, A) in IEX_Message class based on [**IEX TOPS v1.6**](https://iextrading.com/trading/market-data/#specifications) and [**IEX DEEP v1.0**](https://iextrading.com/trading/market-data/#specifications). Even though these classes were created based on the IEX TOPS v1.6, you can parse the message which follows the [**IEX TOPS v1.5**](https://iextrading.com/trading/market-data/#specifications) using these classes.

### IEX_Packet

IEX_Packet class has three member function. The following table shows the description of member functions.
|   function name           |   input   |   output          |   description |
|   ---                     |   ---     |   ---             |   ---         |
|**set_tp_header**          |byte array |-                  |This function parses the IEX packet from the byte array and automatically parses the messages which are included in the packet.|
|**get_messages**           |-          |array of messages  |This function returns the messages which are parsed in the 'set_tp_header' function. |
|**parse_and_get_messages** |byte array |array of messages  |This function is a simple combination of 'set_tp_header' and 'get_messages'. |

### IEX_Message
IEX_Message classes only have **export_json** function. If you init an appropriate Message object using byte array, it will automatically parser all the data, following the Message type.
|   function name           |   input   |   output          |   description |
|   ---                     |   ---     |   ---             |   ---         |
|**__init__**               |byte array |-                  | init a packet using byte array according to a type of the packet |
|**export_json**            |-          |json object        | export an information of the packet as json format. |

e.g.
```python
    # import modules for parsing packet capture file and iex packet.
    import iex_packet
    # rdpcap parsing all the packet which is included in files on memory, PcapReader returns an iterator which iterates packets.
    from scapy.all import rdpcap, PcapReader

    # get iterator for parsing the packet capture file
    packets = PcapReader('example.pcap')

    # create IEX_Packet object for parsing IEX packet
    iex_pkt = IEX_Packet()

    for packet in packets:
        # UDP is used in IEX system. So the captured packet in the IEX history files follows UDP.
        if packet.haslayer('UDP') == True:
            # a payload of UDP packet
            data = packet['Raw'].load
            # parse IEX packet and get the messages which is included in packet.
            messages = iex_pkt.parse_and_get_messages(data)
            # above function returns array of messages.
            for message in messages:
                # print message
                print(message)

                # get the message as a json format and print it.
                message_json = message.export_json()
                print(message_json)
```

## mongodb manager module

### MongoDB_Manager
MongoDB_Manager class supports some queries which are useful to take IEX message data from MongoDB.
It supports 4 functions for querying data.
|   function name           |   input   |   output          |   description |
|   ---                     |   ---     |   ---             |   ---         |
|**__init__**|host, port, db_name, db_user, db_pass|MongoDB_Manager object| host, port: address and port of the mongoDB server, db_name: a name of the database, db_user, db_pass: user name and password who has permissionto modify the database. |
|**drop_collection**|collection|-|drop collection|
|**insert_one**|collection, document|document id|insert one document|
||
|**find_by_datetime**|collection, start_date, end_date |a cursor of query result|find messages using date. (e.g. from 2015-03-24 to 2017-03-24)|
|**find_by_datetime_message_types**|start_date, end_date, msg_types|a cursor of query result|find messages using date and message type. (e.g. from 2015-03-24 to 2017-03-24 & message type: ['T', '8', '5']) |
|**find_by_datetime_symbol**|collection, start_date, end_date, symbol|a cursor of query result|find messages using date and symbol. (e.g. from 2015-03-24 to 2017-03-24 & symbol: NVDA (nvidia nasdaq symbol))|
|**find_by_datetime_symbol_message_types**|collection, start_date, end_date, symbol, msg_types|a cursor of query result  |find messages using data and symbol and message type. (e.g. from 2015-03-24 to 2017-03-24 & message type: ['T', '8', '5'] & symbol: NVDA (nvidia nasdaq symbol))|

an example of push packets from 'pcap' file to mongoDB collection.

```python
    # import module
    import iex_packet
    from mongodb_manager import MongoDB_Manager

    # create mongoDB manager
    mdb_manager = MongoDB_Manager('127.0.0.1', 27017, 'iex_data', 'iex_client', '1234')

    # name of file and collection
    filename = 'iex_deep_v1.pcap'
    collection = 'deep'

    # parsing IEX messages
    iex_pkt = iex_packet.IEX_Packet()
    packets = PcapReader(filename)
    for packet in packets:
        if packet.haslayer('UDP') == True:
            pkt_data = packet['Raw'].load
            messages = iex_pkt.parse_and_get_messages(pkt_data)
            for message in messages:
                json_msg = message.export_json()
                # push the messages to collection
                mdb_manager.insert_one(collection, json_msg)
```

an example of querying data

```python
    # set start and end date in UTC time zone. (UTC time zone is default value of datetime.datetime function. )
    start_date = datetime.datetime(2018, 1, 27, 9, 0, 0, 0, tzinfo=datetime.timezone.utc)
    end_date = datetime.datetime(2018, 1, 27, 18, 0, 0, 0, tzinfo=datetime.timezone.utc)

    # get messages for 'ZXIET' which are generated between start date and end date
    doc_cursor = mdb_manager.find_by_datetime_symbol(collection, start_date, end_date, "ZXIET")
    for doc in doc_cursor:
        print(doc)
```

## How to update your mongoDB databases?
Please use [**update_db.py**](./update_db.py) to update user database.

Usage

```bash
    python update_db.py -i {file path [with or without wildcard charectors]} -c {name of collection} \
    -a {address of mongoDB host} -p {port of mongoDB host} -db {name of data base} -u {user name who has permission} -pw {password of user}
```

e.g. Let's assume that your mongDB server hasn't messages which are generated in 2019-10-24 and you want to add it to 'tops' collection which is included in your database.
If so, you can add it like below.
```bash
    python update_db.py -i 2019-10-24_TOPS_v1.6.pcap -c 'tops' -a '127.0.0.1' -p 27017 -db 'iex_data' -u 'iex_client' -pw '1234'
```