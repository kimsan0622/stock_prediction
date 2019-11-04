# docker pull mongo
# docker run -d --name iex_mongo -p 27017:27017 -v /home/san/nfs/stock_data/mongodb:/data/db -d mongo
# docker exec -it iex_mongo /bin/bash
# mongo
# use admin
# db.createUser({user:"admin",pwd:"admin",roles:[{role:"userAdminAnyDatabase",db:"admin"}]})

# docker run -d --name iex_mongo -p 27017:27017 -v /home/san/nfs/stock_data/mongodb:/data/db -d mongo -auth
# docker exec -it iex_mongo /bin/bash
# mongo -u "admin" -p "admin" -authenticationDatabase "admin"
# use iex_data
# db.createUser({user:"iex_client", pwd:"1234", roles:["dbAdmin", "readWrite"]})

import datetime
import calendar
import time

import pymongo

class MongoDB_Manager(object):
    def __init__(self, host, port, db_name, db_user, db_pass):
        self.connection = pymongo.MongoClient(host=host, port=port)
        self.db = self.connection[db_name]

        # authentication
        self.db.authenticate(db_user, db_pass)
    
    def drop_collection(self, collection):
        return self.db[collection].drop()
    
    def insert_one(self, collection, doc):
        return self.db[collection].insert_one(doc).inserted_id
    
    def insert_many(self, collection, docs):
        return self.db[collection].insert_many(docs)
    
    def find_by_datetime(self, collection, start_date, end_date):
        start_ts = calendar.timegm(start_date.timetuple())
        end_ts = calendar.timegm(end_date.timetuple())
        return self.db[collection].find({'time_stamp': {'$gt': start_ts, '$lt': end_ts}}).sort([("time_stamp", 1)])
    
    def find_by_datetime_message_types(self, collection, start_date, end_date, msg_types=['S']):
        start_ts = calendar.timegm(start_date.timetuple())
        end_ts = calendar.timegm(end_date.timetuple())
        
        return self.db[collection].find({'time_stamp': {'$gt': start_ts, '$lt': end_ts}, 'message_type': {'$in': msg_types}}).sort([("time_stamp", 1)])
    
    def find_by_datetime_symbol(self, collection, start_date, end_date, symbol):
        start_ts = calendar.timegm(start_date.timetuple())
        end_ts = calendar.timegm(end_date.timetuple())
        return self.db[collection].find({'time_stamp': {'$gt': start_ts, '$lt': end_ts}, 'symbol': symbol}).sort([("time_stamp", 1)])

    def find_by_datetime_symbol_message_types(self, collection, start_date, end_date, symbol, msg_types=['S']):
        start_ts = calendar.timegm(start_date.timetuple())
        end_ts = calendar.timegm(end_date.timetuple())
        return self.db[collection].find({'time_stamp': {'$gt': start_ts, '$lt': end_ts}, 'symbol': symbol, 'message_type': {'$in': msg_types}}).sort([("time_stamp", 1)])


if __name__ == "__main__":
    import argparse
    
    from scapy.all import rdpcap, PcapReader
    import iex_packet

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input_file", default='../data/test/deep/20180127_IEXTP1_DEEP1.0.pcap', type=str, help="input file")
    parser.add_argument("-a", "--mongodb_host", default='127.0.0.1', type=str, help="host address of MongoDB server.")
    parser.add_argument("-p", "--mongodb_port", default=27017, type=int, help="host port of MongoDB server.")
    parser.add_argument("-db", "--database_name", default='iex_data', type=str, help="name of database.")
    parser.add_argument("-u", "--database_user", default='iex_client', type=str, help="an authenticated user of the database.")
    parser.add_argument("-pw", "--database_pass", default='1234', type=str, help="a password of the authenticated user.")
    args = parser.parse_args()

    filename = args.input_file

    # access MongoDB
    mdb_manager = MongoDB_Manager(args.mongodb_host, args.mongodb_port, args.database_name, args.database_user, args.database_pass)

    # collection name
    collection = 'test_deep'

    # create iex packet for parsing
    obj = iex_packet.IEX_Packet()

    # drop collection
    mdb_manager.drop_collection(collection)

    # update db
    packets = PcapReader(filename)
    for packet in packets:
        if packet.haslayer('UDP') == True:
            pkt_data = packet['Raw'].load
            messages = obj.parse_and_get_messages(pkt_data)

            for message in messages:
                json_msg = message.export_json()
                print(json_msg)
                mdb_manager.insert_one(collection, json_msg)
    

    start_date = datetime.datetime(2018, 1, 27, 9, 0, 0, 0, tzinfo=datetime.timezone.utc)
    end_date = datetime.datetime(2018, 1, 27, 18, 0, 0, 0, tzinfo=datetime.timezone.utc)

    doc_cursor = mdb_manager.find_by_datetime_symbol(collection, start_date, end_date, "ZXIET")
    for doc in doc_cursor:
        print(doc)
