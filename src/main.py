from dotenv import load_dotenv
from yara_worker import yaraWorker
import requests
import redis
import json
import os

load_dotenv("../.env")
apiurl = os.getenv('API_URL')
host = os.getenv('REDIS_HOST')
port = os.getenv('REDIS_PORT')
password = os.getenv('REDIS_PASSWORD')
base_url = f"http://{os.getenv('FILE_HOST')}:{os.getenv('FILE_PORT')}/scan/"


# redis init
redis = redis.Redis(
    host=host,
    port=port,
    password=password)


sub = redis.pubsub(ignore_subscribe_messages=True)
sub.subscribe('new-scan')

# init yara worker
yara = yaraWorker()
i = 0

print(redis.ping())

def save_json(data,location):
    with open(location, 'w') as outfile:
        json.dump(data, outfile)
    return outfile
    

def matches_json(matches, scan_id):
    json_matches = {}
    summary_json = {}
    for match in matches:
        if match.rule not in ['domain', 'Microsoft_Visual_Cpp_v60']:
            strings = {}
            for i in range(len(match.strings)):
                elem = match.strings[i]
                try:
                    if match.rule in summary_json.keys():
                        summary_json[match.rule] = summary_json[match.rule] + 1
                    else:
                        
                        summary_json[match.rule] = 1
                        
                    selem = elem[2].decode('UTF-8')
                    string = {elem[0]: selem}

                    if elem[1] in strings:
                        strings[elem[1]].append(string)
                    strings[elem[0]] = selem
                    tags = {}
                    for i in range(len(match.tags)):
                        elem = match.tags[i]
                        tags[i] = elem

                    match_json = {'tags': tags, 'strings': strings}

                    json_matches[match.rule] = match_json
                except Exception as e:
                    pass
    save_json(json_matches, f"../result/{scan_id}.json")
    save_json(summary_json, f"../result/{scan_id}.summary.json")


def main():

    for message in sub.listen():
        # print(message)

        data = message.get('data').decode('UTF-8')
        scan_id = data.split(':')[1][1:-2]
        print("scanid : ", scan_id)
        if scan_id is not None:
            try:

                download_url = f"{base_url}{scan_id}/download"
                response = requests.get(download_url)
                file = open(f"../file/{scan_id}", "wb").write(response.content)
                file = open(f"../file/{scan_id}", "rb")
                
                result = yara.analyse(file)

                matches_json(result, scan_id)

                url = f"http://{apiurl}:8080/scan/result/yara"

                multipart_form_data = {
                    'file': (f"{scan_id}.json", open(f"../result/{scan_id}.json", 'rb')),
                    'summary': (f"{scan_id}.summary.json", open(f"../result/{scan_id}.summary.json", 'rb')),
                    'scanid': (None, scan_id),
                }
                res = requests.post(url, data=multipart_form_data)
                print(res.content)
            except Exception as e:
                print(e)


main()
