from dotenv import load_dotenv
from yara_worker import yaraWorker
from os.path import join, dirname
import requests
import redis
import json
import os

load_dotenv(join(dirname(__file__), '.env'))
apiurl = os.getenv('API_URL')
host = os.getenv('REDIS_HOST')
port = os.getenv('REDIS_PORT')
password = os.getenv('REDIS_PASSWORD')
file_host = os.getenv('FILE_HOST')
file_port = os.getenv('FILE_PORT')
base_url = f"http://{file_host}:{file_port}/scan/"


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


def save_json(data, location):
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

    save_json(json_matches, join(dirname(__file__), f"result/{scan_id}.json"))
    save_json(summary_json, join(dirname(__file__),
              f"result/{scan_id}.summary.json"))


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
                file = open(
                    join(dirname(__file__), f"file/{scan_id}"), "wb").write(response.content)
                file = open(
                    join(dirname(__file__), f"file/{scan_id}"), "rb")

                result = yara.analyse(file)

                matches_json(result, scan_id)

                url = f"http://{apiurl}:8080/scan/result/yara"

                summary_json = json.load(
                    open(join(dirname(__file__), f"result/{scan_id}.summary.json"), 'rb'))

                payload = {
                    'scanid': scan_id,
                    'summary': summary_json,
                }

                files = {
                    'file': (f"{scan_id}.json", open(join(dirname(__file__), f"result/{scan_id}.json"), 'rb')),
                }

                print(payload)
                res = requests.post(url, data=payload, files=files)
                print(res.content)
            except Exception as e:
                print(e)


main()
