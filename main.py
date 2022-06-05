import flask
from pymongo  import MongoClient
from flask import request, jsonify
from yara_worker import yaraWorker
import json

#init api
app = flask.Flask(__name__)

#init database
client = MongoClient(host="localhost", port=27017)

#init yara worker
yara = yaraWorker()

def matches_json(matches):
    json_matches = {}
    for match in matches:
        
        strings = {}
        for i in range(len(match.strings)):
            elem = match.strings[i]
            selem = elem[2].decode('UTF-8')
            
            string = {"one":elem[1],"two":selem}
            strings[i] = string
        
        tags = {}
        for i in range(len(match.tags)):
            elem = match.tags[i]
            tags[i] = elem
                
        match_json = {'tags':tags, 'strings':strings}
                      
        json_matches[match.rule] = match_json
    with open('json_data.json', 'w') as outfile:
        json.dump(json_matches, outfile)
    return jsonify(json_matches)

@app.route('/analyse', methods=['POST'])
def analyse():
    
    uploaded_file = request.files['file']
    result = yara.analyse(uploaded_file)

    return matches_json(result)

if __name__ == "__main__":
 app.run(debug=True)