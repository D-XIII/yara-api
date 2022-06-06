from yara_worker import yaraWorker
from flask import request, jsonify
from pymongo  import MongoClient
from dotenv import load_dotenv
import requests
import redis
import json
import os

#init api
# app = flask.Flask(__name__)

#loading data from .env
load_dotenv()
host = os.getenv('REDIS_HOST')
port = os.getenv('REDIS_PORT')
password = os.getenv('REDIS_PASSWORD')
base_url = f"http://{os.getenv('FILE_HOST')}:{os.getenv('FILE_PORT')}/scan/"

#redis init
redis = redis.Redis(
    host= host,
    port= port,
    password= password)

sub = redis.pubsub()
sub.subscribe('new-scan')


#init mongodb
client = MongoClient(host="localhost", port=27017)

#init yara worker
yara = yaraWorker()

i = 0

def matches_json(matches):
    json_matches = {}
    for match in matches:
        if match.rule not in ['domain','Microsoft_Visual_Cpp_v60']:
            strings = {}
            for i in range(len(match.strings)):
                elem = match.strings[i]
                try:
                    
                    selem = elem[2].decode('UTF-8')
                    string = {"variable":elem[1],"value":selem}
                    strings[elem[0]] = string
                    tags = {}
                    for i in range(len(match.tags)):
                        elem = match.tags[i]
                        tags[i] = elem
                            
                    match_json = {'tags':tags, 'strings':strings}
                                
                    json_matches[match.rule] = match_json
                except:
                    print(elem[2])
             
    with open('json_data.json', 'w') as outfile:
        json.dump(json_matches, outfile)
    return jsonify(json_matches)

for message in sub.listen():
    print(++i)
    # if message is not None and isinstance(message, dict):
    # scan_id = message.get('scanid')
    scan_id = 'c05cd1e35e88707da070cfbd93fd4f1f'
    download_url = f"{base_url}{scan_id}/download"
    response = requests.get(download_url)
    file = open(scan_id, "wb").write(response.content)
    # file.close()
    file = open(scan_id, "rb")
    # print(response.content)
    result = yara.analyse(file)

    presult = matches_json(result)

# @app.route('/analyse', methods=['POST'])
# def analyse():
    
#     uploaded_file = request.files['file']
#     result = yara.analyse(uploaded_file)

#     return matches_json(result)

# if __name__ == "__main__":
#  app.run(debug=True)