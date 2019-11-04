#include <chrono>

#include "iex_packet.hpp"

#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "PayloadLayer.h"

#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/json.hpp>

#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>    //

#include <vector>   //std::vector
#include <map>  // std::map
#include <stdlib.h> // atoi
/*
    for PcapPlusPlus
    pkg-config
        c++ --std=c++11 <input>.cpp $(pkg-config --cflags --libs PcapPlusPlus)
    
    native
        c++ --std=c++11 <input>.cpp
            -I/usr/local/include/pcapplusplus -I/usr/include/netinet \
            -lPcap++ -lPacket++ -lCommon++ -lpcap -lpthread
*/

/*
    for mongodb
    pkg-config
        c++ --std=c++11 <input>.cpp $(pkg-config --cflags --libs libmongocxx)
    
    native
        c++ --std=c++11 <input>.cpp
            -I/usr/local/include/mongocxx/v_noabi -I/usr/local/include/libmongoc-1.0 \
            -I/usr/local/include/bsoncxx/v_noabi -I/usr/local/include/libbson-1.0 \
            -L/usr/local/lib -lmongocxx -lbsoncxx
*/

/*
    for jsoncpp
    pkg-config
        c++ --std=c++11 <input>.cpp $(pkg-config --cflags --libs jsoncpp)
    
    native
        c++ --std=c++11 <input>.cpp
            -I/usr/local/include -L/usr/local/lib -ljsoncpp
*/

// g++ --std=c++11 update_db.cpp -o update_db $(pkg-config --cflags --libs libmongocxx PcapPlusPlus)
// g++ --std=c++11 update_db.cpp -o update_db $(pkg-config --cflags --libs libmongocxx PcapPlusPlus jsoncpp) -DENABLE_JSONCPP

bsoncxx::document::value parse_as_doc(std::stringstream &sstream){
    bsoncxx::builder::stream::document document{};

    std::string key;
    std::string type;
    
    std::string value_s;
    double value_d;
    uint8_t value_ui8;
    int64_t value_i64;
    uint64_t value_ui64;
    bool value_b;


    while(sstream >> key){
        sstream >> type;

        if (type == "string"){
            sstream >> value_s;
        }
        else if (type == "double"){
            sstream >> value_d;
        }
        else if (type == "uint8_t"){
            sstream >> value_ui8;
        }
        else if (type == "uint32_t"){
            sstream >> value_i64;
        }
        else if (type == "int64_t"){
            sstream >> value_i64;
        }
        else if (type == "char"){
            sstream >> value_s;
        }
        else if (type == "bool"){
            sstream >> value_b;
        }
        else if (type == "uint64_t"){
            sstream >> value_i64;
        }


        if (type == "string"){
            document << key << value_s;
        }
        else if (type == "double"){
            document << key << value_d;
        }
        else if (type == "uint8_t"){
            document << key << value_ui8;
        }
        else if (type == "uint32_t"){
            document << key << value_i64;
        }
        else if (type == "int64_t"){
            document << key << value_i64;
        }
        else if (type == "char"){
            document << key << value_s;
        }
        else if (type == "bool"){
            document << key << value_b;
        }
        else if (type == "uint64_t"){
            document << key << value_i64;
        }
    }

    bsoncxx::document::value doc = document << bsoncxx::builder::stream::finalize;

    return doc;
}

int parse_arguments(std::map<std::string, std::string> arguments, std::string &input_path, std::string &collection, std::string &mongodb_host, std::string &mongodb_port, std::string &database_name, std::string &database_user, std::string &database_pass, std::string &drop_collection, std::string &verbose_mode, int &insert_batch_size){
    // parsing arguments
    if (arguments["-i"] != ""){
        input_path = arguments["-i"];
    }
    if (arguments["-c"] != ""){
        collection = arguments["-c"];
    }
    if (arguments["-a"] != ""){
        mongodb_host = arguments["-a"];
    }
    if (arguments["-p"] != ""){
        mongodb_port = arguments["-p"];
    }
    if (arguments["-db"] != ""){
        database_name = arguments["-db"];
    }
    if (arguments["-u"] != ""){
        database_user = arguments["-u"];
    }
    if (arguments["-pw"] != ""){
        database_pass = arguments["-pw"];
    }
    if (arguments["-dc"] != ""){
        drop_collection = arguments["-dc"];
    }
    if (arguments["-v"] != ""){
        verbose_mode = arguments["-v"];
    }
    if (arguments["-ibs"] != ""){
        insert_batch_size = atoi(arguments["-ibs"].c_str());
    }
    return 0;
}

// ./update_db -c tops -ibs 30000 -i /home/san/backup/workspace/stock_prediction/iex/data/raw_data/tops/2018-08-02_TOPS_v1.6.pcap
// ./update_db -c tops -ibs 50000 -i /home/san/backup/workspace/stock_prediction/iex/data/raw_data/tops/2018-08-02_TOPS_v1.6.pcap
// find /home/san/backup/workspace/stock_prediction/iex/data/raw_data/tops/*.pcap | xargs -l ./update_db -c tops -ibs 50000 -dc false -v true -i 

int main(int argc, char* argv[])
{
    // parsing arguments
    std::map<std::string, std::string> arguments;
    if (argc%2 == 0 || argc < 2){
        std::cout<<"Usage\n\t-i: path to input file\n\t-c[tops]: name of collection\n\t-a[127.0.0.1]: mongodb_host addr\n\t-p[27017]: mongodb_host port\n\t-db[iex_data]: name of database\n\t-u[iex_client]: user name\n\t-pw[1234]: user password\n\t-dc[true]: drop collection flag\n\t-ibs[50000]: size of insert batch\n\t-v[false]: verbose mode\n\n"<<std::endl;
    }
    for (int i = 1; i < argc ; i+=2){
        arguments[std::string(argv[i])] = std::string(argv[i+1]);
    }
    std::cout<<arguments["-v"] <<std::endl;

    std::string input_path = "";
    std::string collection_name = "tops";
    std::string mongodb_host = "127.0.0.1";
    std::string mongodb_port = "27017";
    std::string database_name = "iex_data";
    std::string database_user = "iex_client";
    std::string database_pass = "1234";
    std::string drop_collection = "true";
    std::string verbose_mode = "false";
    int insert_batch_size = 50000;

    parse_arguments(arguments, input_path, collection_name, mongodb_host, mongodb_port, database_name, database_user, database_pass, drop_collection, verbose_mode, insert_batch_size);
    pcpp::PcapFileReaderDevice reader(input_path.c_str());

    if (!reader.open())
    {
        printf("Error opening the pcap file\n");
        return 1;
    }

    // raw packet object
    pcpp::RawPacket rawPacket;
    // packet pointer
    const uint8_t* packet_ptr_;

    // packet counter
    int cnt = 0;
    int sec_cnt = 0;
    std::chrono::system_clock::time_point start = std::chrono::system_clock::now();

    // for parsing iex tp packet
    iex::IEX_Packet iex_pkt;

    // mongo db
    std::string mongodb_url = std::string("mongodb://") + database_user + std::string(":") + database_pass + std::string("@") + mongodb_host + std::string("/?authSource=") + database_name;
    mongocxx::instance inst{};
    mongocxx::client conn = mongocxx::client{mongocxx::uri{mongodb_url.c_str()}};
    auto collection = conn[database_name.c_str()][collection_name.c_str()];

    // drop collection
    if (drop_collection == "true"){
        if (verbose_mode == "true"){
            std::cout<<"drop collection: "<<collection_name<<std::endl;
        }
        collection.drop();
    }

    // string stream for parsing a string which is exported from iex_packet object by calling 'export_str'
    std::stringstream sstream;
    // packet string
    std::string pkt_str;

    // list of document
    std::vector<bsoncxx::document::value> documents;

    std::cout<<"target: "<<input_path<<std::endl;

    // read Layer 3 Packet (TCP, UDP)
    while (reader.getNextPacket(rawPacket))
    {
        // parsing packet
        pcpp::Packet parsedPacket(&rawPacket);
        
        // get payload and data
        pcpp::PayloadLayer* payload_layer = parsedPacket.getLayerOfType<pcpp::PayloadLayer>();
        packet_ptr_ = payload_layer->getData();

        // parsing IEX_TP packet and get messages
        std::vector<std::shared_ptr<iex::IEX_Message> > obj_vector = iex_pkt.parse_and_get_messages(packet_ptr_);

        // get data of message as string and parsing it.
        // then, make it as document(bson type) and push it to the list
        for (std::vector<std::shared_ptr<iex::IEX_Message> >::iterator it = obj_vector.begin() ; it != obj_vector.end(); ++it){
            // get string
            pkt_str = (*it)->export_str();
            // set a string to the string stream object
            sstream.clear();
            sstream.str(pkt_str);

            // parsing the string and make it as document type
            bsoncxx::document::value doc = parse_as_doc(sstream);
            // push the document
            documents.push_back(doc);
        }

        // if a number of elements wich is included in list is bigger than 'insert_batch_size', insert them to the collection
        if (documents.size() > insert_batch_size){
            collection.insert_many(documents);
            documents.clear();
        }
        
        // count packet
        cnt += 1;
        std::chrono::duration<double> sec = std::chrono::system_clock::now() - start;
        if (sec.count() > 1){
            if (verbose_mode == "true"){
                printf("processing packets: %d iters/sec\n", cnt);
            }
            cnt = 0;
            sec_cnt += 1;
            start = std::chrono::system_clock::now();
        }
    }

    if (verbose_mode == "true"){
        printf("processing packets: %d iters/sec\n", cnt);
    }

    if (documents.size()>0){
        collection.insert_many(documents);
        documents.clear();
    }

    if (verbose_mode == "true"){
        printf("elapsed time: %d sec", sec_cnt);
    }
    reader.close();

    // is it inserted collectly?
    // auto cursor = collection.find({});

    // for (auto&& doc : cursor) {
    //     std::cout << bsoncxx::to_json(doc) << std::endl;
    // }

    return 0;
}