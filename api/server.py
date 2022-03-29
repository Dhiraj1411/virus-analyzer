from flask import Flask, request, send_from_directory, render_template
from flask_restful import Resource, Api
from werkzeug.utils import secure_filename
import datetime
import requests
import json
from flask_cors import CORS
from datetime import date
import sys
import os

app = Flask(__name__, static_folder='./build', static_url_path='/')
api = Api(app)
CORS(app)
port = 5000

if sys.argv.__len__() > 1:
    port = sys.argv[1]
print("Api running on port : {} ".format(port))

def getjson():
    # json_file = open("data.json", 'r')
    # object = json_file.read()
    file_exists = os.path.exists('data.json')

    print("file_exists")
    print(file_exists)

    if file_exists:
        with open("data.json", "r") as read_file:
            if read_file is not None:
                object = json.load(read_file)
                # object = read_file.read();
                if object is not None:
                    response = {
                        "data" : []
                    }
                    objdata = object["data"]
                    # print("===============")
                    # print(objdata)
                    for item in objdata:
                        detail = {
                            "hash_key":item["hash_key"],
                            "detection_name":item['detection_name'],
                            "number_of_engine": item['number_of_engine'],
                            "scan_date" : item['scan_date']
                        }
                        response['data'].append(detail)
                    if len(response['data']) > 0:
                        return json.dumps(response)
                    else:
                        return json.dumps({"data":[]})
                else:
                    return json.dumps({"data":[]})
        read_file.close()
    else:
        return []

def isHaskeyExpired(hashkey, local_data):
    print("I am in isHashKeyExpired")
    print(hashkey)
    print(local_data)
    if hashkey in local_data:
        data = local_data['haskey']
        if "scan_date" in data:
            scanDate = data['scan_date']
            d0 = date(scanDate)
            print("Scan date: "+scanDate)
            d1 = datetime.datetime.now()
            delta = d1 - d0
            noOfDays = delta.days
            print("no of days: "+noOfDays)
            if noOfDays > 1:
                return True

    return False

def getUnmappedOrExpiredHashkey (filename, local_data):
    hashKeyList = []
    local_stored_hashkey = {}
    for item in local_data:
        local_stored_hashkey[item['hash_key']] = {
            "detection_name": item["detection_name"], 
            "number_of_engine": item["number_of_engine"], 
            "scan_date": item["scan_date"]
        }
    print("^^^^^^^^^^^^^^^^^^^^^^^^^^^")
    print(local_stored_hashkey)
    if local_data is not None:
        with open(filename) as f:
            for hash in f:
                if hash in local_stored_hashkey:
                    if isHaskeyExpired(local_stored_hashkey[hash]['scan_date'], local_data):
                        hashKeyList.append(hash)
                else:
                    hashKeyList.append(hash)
        f.close()
    else:
        with open(filename) as f:
             for hash in f:
                hashKeyList.append(hash)
        f.close()
    return hashKeyList

def saveDataInJson(response, localData):
    # print("Response: ")
    # print(response)
    # print(type(response))
    # print("LocalData: ")
    # print(localData)
    # print(type(localData));
    final_output = {
        "data":[]
    }
    if len(response) > 0 :
        for data in response:
            final_output["data"].append(data)

    if len(localData['data']) > 0:
        for data1 in localData['data']:
            print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
            print(data1)
            final_output["data"].append(data1)
    
    if final_output is not None:
        with open("data.json", "w") as jsonFile:
            jsonFile.write(json.dumps(final_output,indent=4, sort_keys=True, default=str))
        jsonFile.close()
    return final_output

@app.route('/')
def home():
    return app.send_static_file('index.html')

@app.route('/test')
def test():
    return "Hello From Docker"

@app.route('/getdata')
def getData():
    return getjson()

@app.route('/upload',methods = ['POST'])
def uploadFile():
    file= request.files['file']
    filename = secure_filename(file.filename) 
    file.save(os.path.join(filename))
    responseObject = []
    
    with open("data.json") as readJsonData:
        local_data = json.load(readJsonData)
        
    
    # print("**********************************")
    # print(local_data)
    # print(type(local_data))
    # print("####################################")
    # print(local_data["data"])
    hashList = getUnmappedOrExpiredHashkey(filename, local_data["data"])
    # print("HashList: ")
    # print(hashList)
    for line in hashList:
        print("https://www.virustotal.com/api/v3/files/"+line.strip());  
        req=requests.get("https://www.virustotal.com/api/v3/files/"+line.strip(), headers={"x-apikey": "4fe780bd9b32c34f4f7e9b7c6ff12569961618cda34096355771a958e2fc4bec"})
        resp = req.json()
        
        if req.status_code == 200:
            if 'data' in resp:
                if 'attributes' in resp['data']:
                    if 'meaningful_name' in resp['data']['attributes']:
                        meaningful_name = resp['data']['attributes']['meaningful_name']

            if 'data' in resp:
                if 'attributes' in resp['data']:
                    if 'names' in resp['data']['attributes']:
                        names = resp['data']['attributes']['names']

            detail = {
                "hash_key":line.strip(),
                "detection_name":meaningful_name,
                "number_of_engine": len(names),
                "scan_date" : datetime.datetime.now()
            }
            responseObject.append(detail)
        else:
            detail = {
                "hash_key":line.strip(),
                "detection_name":"null",
                "number_of_engine": "null",
                "scan_date" : datetime.datetime.now()
            }
            responseObject.append(detail)
    # print("&&&&&&&&&&&&&&&&&&&&&&&&&")
    return saveDataInJson(responseObject,local_data)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=port);