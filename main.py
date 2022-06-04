import flask
from flask import request, jsonify
from yara_worker import yaraWorker
import json

app = flask.Flask(__name__)
app.config["DEBUG"] = True

yara = yaraWorker()

def matches_json(matches):
    json_matches = []
    for match in matches:
        print(type(match.rule))
        print(type(match.strings))
        print(type(match.tags))
        
        tags = tuple(match.tags)
        strings = tuple(match.strings)
        match_json = {match.rule:{  'tags':strings, 
                                    'strings':match.strings
                                }
                      }
        json_matches.append(match_json)
    return json_matches

@app.route('/analyse', methods=['POST'])
def analyse():
    uploaded_file = request.files['file']
    result = yara.analyse(uploaded_file)
    
    # print(type(result[0]))
    # print(json.dumps(result[0].__dict__))
    
    # print(*result, sep = "\n") 
    return matches_json(result)
    return {"test": "test"}



# f = open('samples/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.exe','rb')

if __name__ == "__main__":
 app.run(debug=True)