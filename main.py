from threading import Thread
from yara_worker import yaraWorker
from flask import request, Flask, send_file
from dotenv import load_dotenv
import requests
import redis
import json
import os

#init api

def api():
    app = Flask("yara service")
    @app.route('/downloadresult', methods=['GET'])
    def downloadFile():
        
        scan_id = request.args.get('scanid')
        print(scan_id)
        if scan_id is not None:
            download_url = f"{base_url}{scan_id}/download"
            response = requests.get(download_url)
            file = open(f"./result/{scan_id}.json", "rb")
            # print(file)
            return send_file(file, as_attachment=True,download_name=f"{scan_id}.json")
        else:
            return "No scan id"

    app.run(debug=False,port=8877)
    
Thread(target=api).start()



#loading data from .env
load_dotenv()
apiurl = os.getenv('API_URL')
host = os.getenv('REDIS_HOST')
port = os.getenv('REDIS_PORT')
password = os.getenv('REDIS_PASSWORD')
base_url = f"http://{os.getenv('FILE_HOST')}:{os.getenv('FILE_PORT')}/scan/"

#redis init
redis = redis.Redis(
    host= host,
    port= port,
    password= password)

sub = redis.pubsub(ignore_subscribe_messages=True)
sub.subscribe('tmp-new-scan')

#init yara worker
yara = yaraWorker()

i = 0

def matches_json(matches,scan_id):
    json_matches = {}
    for match in matches:
        if match.rule not in ['domain','Microsoft_Visual_Cpp_v60']:
            strings = {}
            for i in range(len(match.strings)):
                elem = match.strings[i]
                try:
                    
                    selem = elem[2].decode('UTF-8')
                    string = {elem[0]:selem}
                    
                    if elem[1] in strings:
                        strings[elem[1]].append(string)
                    strings[elem[0]] = selem
                    tags = {}
                    for i in range(len(match.tags)):
                        elem = match.tags[i]
                        tags[i] = elem
                            
                    match_json = {'tags':tags, 'strings':strings}
                                
                    json_matches[match.rule] = match_json
                except:
                    pass
             
    with open(f"./result/{scan_id}.json", 'w') as outfile:
        json.dump(json_matches, outfile)
    return outfile

def main():
    for message in sub.listen():
        print(++i)
        print(message)

        data = message.get('data').decode('UTF-8')
        scan_id = data.split(':')[1][1:-2]
        print("scanid : ", scan_id)
        if scan_id is not None:
            
            download_url = f"{base_url}{scan_id}/download"
            response = requests.get(download_url)
            file = open(f"./file/{scan_id}", "wb").write(response.content)
            file = open(f"./file/{scan_id}", "rb")
            result = yara.analyse(file)

            presult = matches_json(result,scan_id)
        
        try:
            url = f"http://{apiurl}:8080/result/yara"
            myobj = {
                'scanId': scan_id,
                'filename': f"{scan_id}.json"
                }

            res = requests.post(url, data = myobj)
            print(res)
        except:
            pass

main()