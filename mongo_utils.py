from typing import Collection
import pymongo

myclient = pymongo.MongoClient("mongodb://localhost:27017/")
# db = myclient["file-split"]
db = myclient["userReg"]
Collection = db["poa"] #POA = Proof of Authenticiy
def insert_into_mongo(filename,merkle_root):
    data = {
        "filename":filename,
        "merkle_root":merkle_root
    }
    is_exist = list(Collection.find({"filename":filename}))
    print(is_exist)
    if is_exist == []:
        print("New file")
        done = Collection.insert_one(data)
        if done == None:
            print ("Some problem with Mongo DB. Check the database")
        else:
            query = {"filename":filename}
            update = {"$set" : {"merkle_root" : merkle_root}}
            done = Collection.update_one(query,update)
            print(done)
        if done == None:
            print ("Some problem with Mongo DB. Check the database")

def find_mongo(filename):
    query = {
        "filename":filename
    }
    data = list(Collection.find(query))
    if data == {}:
        return None
    else:
        return data[0]["merkle_root"] 
