from flask import Flask, request, send_from_directory, render_template
from flask_restful import Resource, Api
from werkzeug.utils import secure_filename
import datetime
import requests
import json
from flask_cors import CORS
import sys
import os

app = Flask(__name__, static_folder='./build', static_url_path='/')
api = Api(app)
CORS(app)
port = 8080

if sys.argv.__len__() > 1:
    port = sys.argv[1]
print("Api running on port : {} ".format(port))

@app.route('/')
def home():
    return app.send_static_file('index.html')

@app.route('/test')
def test():
    return "Hello From Docker"
    
@app.route('/upload',methods = ['POST'])
def uploadFile():
    file= request.files['file']
    filename = secure_filename(file.filename) 
    file.save(os.path.join(filename))
    response = []
    with open(filename) as f:
        for line in f:
            # print("https://www.virustotal.com/api/v3/files/"+line.strip());
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

                response.append({
                    "hash_key":line.strip(),
                    "detection_name":meaningful_name,
                    "number_of_engine": len(names),
                    "scan_date" : datetime.datetime.now()
                })
            else:
                response.append({
                    "hash_key":line.strip(),
                    "detection_name":"null",
                    "number_of_engine": "null",
                    "scan_date" : datetime.datetime.now()
                })
    # print(response);
    return {'data': response}

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=port);