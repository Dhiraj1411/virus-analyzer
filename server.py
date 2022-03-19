from flask import Flask, request
from flask_restful import Resource, Api
from werkzeug.utils import secure_filename
import requests
import json
from flask_cors import CORS
import sys
import os

app = Flask(__name__)
api = Api(app)
CORS(app)
port = 8080

if sys.argv.__len__() > 1:
    port = sys.argv[1]
print("Api running on port : {} ".format(port))

@app.route('/')
def get(self):
    return {'hello': 'world'}
    
@app.route('/upload',methods = ['POST'])
def uploadFile():
    file= request.files['file']
    filename = secure_filename(file.filename) 
    file.save(os.path.join(filename))
    dict1 = []
    with open(filename) as f:
        # file_content = f.read()
        for line in f:
            dict1.append(line.strip())
            print("https://www.virustotal.com/api/v3/files/"+line.strip());
            req=requests.get("/https://www.virustotal.com/api/v3/files/0496f4962d3dce3caa849f605749f7f2 HTTP/1.1", headers={"x-apikey": "4fe780bd9b32c34f4f7e9b7c6ff12569961618cda34096355771a958e2fc4bec"})
            print(req)
    # This dict1 has all the hash value in an array, If we get the proper
    # api we can iterate over and call the api and build the json
    print(dict1)
    return {'hashkey': dict1}

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=port);