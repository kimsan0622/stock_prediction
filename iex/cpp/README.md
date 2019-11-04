# IEX data Preprocessing module (cpp)

The functions of CPP IEX data preprocessing module are almost same with python module. But it's more faster than python module.

## How to build it

You need to install [PcapPlusPlus](https://pcapplusplus.github.io/docs/quickstart/linux#step-1---install-pcapplusplus) module and [mongocxx](http://mongocxx.org/) module.
If you want to build **iex_packet.hpp** with [JSONCPP](https://github.com/open-source-parsers/jsoncpp) module, pass the **-DENABLE_JSONCPP** flag when you build it.
JSONCPP is an option that make it possible to export the data as JSON format. But you don't need to build with it. Because **update_db.cpp" don't use that fuction.


| `file name` | `dependencies` |
| --- | --- |
| **iex_packet.hpp** | optional: JSONCPP |
| **update_db.cpp** | PcapPlusPlus, mongocxx |

- If you use pkg-config.

```bash
    g++ --std=c++11 update_db.cpp -o update_db $(pkg-config --cflags --libs libmongocxx PcapPlusPlus)
    
    # if you want to build it with JSONCPP
    g++ --std=c++11 update_db.cpp -o update_db $(pkg-config --cflags --libs libmongocxx PcapPlusPlus jsoncpp) -DENABLE_JSONCPP
```

- If you don't use pkg-config.
 
```bash
    g++ --std=c++11 update_db.cpp -o update_db
            -I/usr/local/include/pcapplusplus -I/usr/include/netinet \
            -I/usr/local/include/mongocxx/v_noabi -I/usr/local/include/libmongoc-1.0 \
            -I/usr/local/include/bsoncxx/v_noabi -I/usr/local/include/libbson-1.0 \
            -lPcap++ -lPacket++ -lCommon++ -lpcap -lpthread \
            -L/usr/local/lib -lmongocxx -lbsoncxx
    
    # if you want to build it with JSONCPP
    g++ --std=c++11 update_db.cpp -o update_db
            -I/usr/local/include/pcapplusplus -I/usr/include/netinet -I/usr/local/include \
            -I/usr/local/include/mongocxx/v_noabi -I/usr/local/include/libmongoc-1.0 \
            -I/usr/local/include/bsoncxx/v_noabi -I/usr/local/include/libbson-1.0 \
            -lPcap++ -lPacket++ -lCommon++ -lpcap -lpthread \
            -L/usr/local/lib -lmongocxx -lbsoncxx \
            -L/usr/local/lib -ljsoncpp
```

## iex packet module

iex_packet module has two types of class. one is IEX_Packet class, another is IEX_Message class.
IEX_Packet class parse a IEX-TP packet which follows the IEX Transport Protocol. (You can find the specification of IEX-TP v1 in [**here**](https://iextrading.com/trading/market-data/#specifications))
Therefore, you can parser the IEX packet from a packet capture file using this class and packet capture parser.
I recommend you to use the 'scapy' module for parsing a packet capture file (This kind of files usually get **.pcap** as an extension.).
There are 13 subclasses (**S, D, H, O, P, E, 8, 5, Q, T, X, B, A**) in IEX_Message class based on [**IEX TOPS v1.6**](https://iextrading.com/trading/market-data/#specifications) and [**IEX DEEP v1.0**](https://iextrading.com/trading/market-data/#specifications). Even though these classes were created based on the IEX TOPS v1.6, you can parse the message which follows the [**IEX TOPS v1.5**](https://iextrading.com/trading/market-data/#specifications) using these classes.

### IEX_Packet

IEX_Packet class has three member function. The following table shows the description of member functions.

| `function name` | `input` | `output` | `description` |
| --- | --- | --- | --- |
| **set_tp_header** | byte array | - | This function parses the IEX packet from the byte array and automatically parses the messages which are included in the packet. |
| **get_messages** | - | array of messages | This function returns the messages which are parsed in the 'set_tp_header' function. |
| **parse_and_get_messages** | byte array | array of messages | This function is a simple combination of 'set_tp_header' and 'get_messages'. |

### IEX_Message

IEX_Message classes only have **export_json** function. If you init an appropriate Message object using byte array, it will automatically parser all the data, following the Message type.

| `function name` | `input` | `output` | `description` |
| --- | --- | --- | --- |
| **__init__** | byte array | - | init a packet using byte array according to a type of the packet. |
| **export_str** | - | string | export an information of the packet as string. a string consists of lines, and each line is a key-type-value string with delimiter " ". e.g. "message_type char A\n" |
| **export_json** | - | json object | export an information of the packet as json format. |


## How to update your mongoDB databases

Please use **update_db** to update user database.

Usage

```bash
    ./update_db -i {file path}  -dc {drop_collection: true or false } -v {verbose mode: true or false } \
        -c {name of collection} -a {address of mongoDB host} -p {port of mongoDB host} \
        -db {name of data base} -u {user name who has permission} -pw {password of user} -ibs {insert batch size}
```

e.g. Let's assume that your mongDB server hasn't messages which are generated in 2019-10-24 and you want to add it to 'tops' collection which is included in your database.
If so, you can add it like below.

```bash
    ./update_db -i 2019-10-24_TOPS_v1.6.pcap -c 'tops' \
        -a '127.0.0.1' -p 27017 -db 'iex_data' -u 'iex_client' -pw '1234' -ibs 50000
```

If you want to update many files, Please use **xargs**.

e.g.

```bash
    find ./tops/*.pcap | xargs -l ./update_db -c tops -ibs 50000 -dc false -v true -i 
```