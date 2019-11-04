import argparse
import glob

import tqdm 
from scapy.all import rdpcap, PcapReader

import iex_packet
from mongodb_manager import MongoDB_Manager

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input_path", default='../data/test/tops/*.pcap', type=str, help="input path [with wildcard characters]")
    parser.add_argument("-c", "--collection", default='tops', type=str, help="name of collection")
    parser.add_argument("-a", "--mongodb_host", default='127.0.0.1', type=str, help="host address of MongoDB server.")
    parser.add_argument("-p", "--mongodb_port", default=27017, type=int, help="host port of MongoDB server.")
    parser.add_argument("-db", "--database_name", default='iex_data', type=str, help="name of database.")
    parser.add_argument("-u", "--database_user", default='iex_client', type=str, help="an authenticated user of the database.")
    parser.add_argument("-pw", "--database_pass", default='1234', type=str, help="a password of the authenticated user.")
    parser.add_argument("-dc", "--drop_collection", dest="drop_collection", action="store_true", help="if it is true, drop collection before update it. default value is false.")
    parser.add_argument("-ibs", "--insert_batch_size", default=10000, type=int, help="size of insert batch")
    parser.set_defaults(drop_collection=False)
    args = parser.parse_args()

    filenames = glob.glob(args.input_path)

    # access MongoDB
    mdb_manager = MongoDB_Manager(args.mongodb_host, args.mongodb_port, args.database_name, args.database_user, args.database_pass)

    # collection name
    collection = args.collection

    # create iex packet for parsing
    obj = iex_packet.IEX_Packet()

    # size of insert batch
    insert_batch_size = args.insert_batch_size
    docs = list()

    # drop collection
    if args.drop_collection:
        print('drop collection: {0}'.format(collection))
        mdb_manager.drop_collection(collection)

    # update db
    for filename in tqdm.tqdm(filenames, desc='file name: '):
        packets = PcapReader(filename)
        for packet in tqdm.tqdm(packets, desc='UDP pkts: '):
            if packet.haslayer('UDP') == True:
                pkt_data = packet['Raw'].load
                messages = obj.parse_and_get_messages(pkt_data)

                for message in messages:
                    json_msg = message.export_json()
                    docs.append(json_msg)
                    # mdb_manager.insert_one(collection, json_msg)
                
            if len(docs) > insert_batch_size:
                mdb_manager.insert_many(collection, docs)
                docs = list()
        if len(docs) > 0:
            mdb_manager.insert_many(collection, docs)
            docs = list()