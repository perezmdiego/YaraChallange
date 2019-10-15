import os
import json
import logging

from yararule import YaraRule, db
from yarascan import YaraScan
from flask import Flask, jsonify, request
from logging.handlers import RotatingFileHandler
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy_utils import create_database, database_exists, drop_database
#================================================================================================================================#


# ++++++++++++++++++++++++++
# +  FLASK Configuration   +
# ++++++++++++++++++++++++++


app = Flask(__name__)
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(PROJECT_ROOT, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
DB_USER = 'root'
DB_PASSWORD = ''
DB_HOST = 'localhost'
DB_NAME = 'yararules'
DB_URL = 'mysql://{}:{}@{}/{}'.format(DB_USER, DB_PASSWORD, DB_HOST, DB_NAME)
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.app_context().push()

#================================================================================================================================#


# ++++++++++++++++++++++++++
# +    Errors Handlers     +
# ++++++++++++++++++++++++++

@app.errorhandler(400) 
def bad_request(e):
    app.logger.error("{}: {}".format(e, request.url)) 
    return jsonify({'errorCode' : 400, 'message' : 'Bad Request'}), 400

@app.errorhandler(404) 
def invalid_route(e):
    app.logger.error("{}: {}".format(e, request.url)) 
    return jsonify({'errorCode' : 404, 'message' : 'Route not found'}), 404

@app.errorhandler(500)
def server_error(e):
    app.logger.error("{}".format(e))
    return jsonify({'errorCode' : 500, 'message' : 'Server error'}), 500

@app.route('/api/rule/all', methods=['GET'])
def getAllRules():
    rules = YaraRule.query.all()
    yara_rules = []
    for rule in rules:
        yara_rules.append(rule.to_json())
    return jsonify({'rules':yara_rules}), 200

#================================================================================================================================#

# +++++++++++++++++++++
# +  Add Rule Method  +
# +++++++++++++++++++++

@app.route('/api/rule/<int:id>', methods=['GET'])
def getRule(id):
    rule = YaraRule.query.get(id)
    if rule == None:
        result = jsonify({'Error':'No existe regla para ese Id, ingrese uno nuevo.'})
    else:
        result = rule.to_json()
    return result, 200

@app.route('/api/rule', methods=['POST'])
def addRule():
    if request.is_json:
        try:
            req = request.get_json()
            rule = YaraRule(**req)
            db.session.add(rule)
            db.session.commit()
            result =rule.to_json()
            return result, 201

        except SQLAlchemyError as e:
            return jsonify({'Error':str(e)})

@app.route('/api/rule/<int:id>', methods=['PUT'])
def updateRule(id):

    if request.is_json:
        try:
            req = request.get_json()
            rule = YaraRule.query.get(id)
            if rule == None:
                return jsonify({'Error':'No existe regla para ese Id, ingrese uno nuevo.'})               
            else:
                updated_rule = db.session.query(YaraRule).filter(YaraRule.id == id).update(req)
                db.session.commit()
                YaraRule.query.get(id)
                app.logger.info('Se actualizo la regla de yara con el ID: {}'.format(str(id)))
                return jsonify({'updated':rule.to_json()})

        except SQLAlchemyError as e:
            return jsonify({'Error':str(e)})

#================================================================================================================================#


# ++++++++++++++++++++++++++
# +  Text Analyze  Method  +
# ++++++++++++++++++++++++++


@app.route('/api/analyze/text', methods=['POST'])
def analyzeText():
    resultados = []
    print(request)
    
    if request.is_json:
        try:
            req = request.get_json()
            rules_id = [str(item['rule_id']) for item in req['rules']]
            rules = db.session.query(YaraRule).filter(YaraRule.id.in_([*rules_id])).all()
            if len(rules) > 0:
                yaraRules_dict = dict([(str(rule.id), rule.rule) for rule in rules])
                data = req['text']
                yarascanObject = YaraScan(data, yaraRules_dict)
                scan_result = yarascanObject.result
                db.session.add(yarascanObject)
                db.session.commit()
                app.logger.info('Se realizo un analisis sobre el texto: "{}"'.format(req['text']))
                result = jsonify({"status": "ok",'results':scan_result})
            else:
                result = jsonify({'Error':'No existe regla para ese Id, ingrese uno nuevo.'})
            return result,200

        except  KeyError as e:
            app.logger.error('Ocurrio el siguiente error al analizar un texto: No se encontro la llave "{}" dentro del json'.format(str(e)))
            return jsonify({'Error': 'No se encontro la llave "{}" dentro del json'.format(str(e))})

#================================================================================================================================#
    

# ++++++++++++++++++++++++++
# +  File Analyze  Method  +
# ++++++++++++++++++++++++++

@app.route('/api/analyze/file', methods=['POST'])
def analyzeFile():
    if 'file' in request.files:
        rules_id = request.form['rules'].split(',')
        file = request.files['file']
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        rules = db.session.query(YaraRule).filter(YaraRule.id.in_([*rules_id])).all()
        yaraRules_dict = dict([(str(rule.id), rule.rule) for rule in rules])
        data = filepath
        yarascanObject = YaraScan(data, yaraRules_dict)
        scan_result = yarascanObject.result
        db.session.add(yarascanObject)
        db.session.commit()
        app.logger.info('Se realizo un analisis sobre el archivo: "{}"'.format(filename))
    return {"status": "ok",'results':scan_result}, 200

#================================================================================================================================#

# ++++++++++++++++++++++++++
# +        MAIN            +
# ++++++++++++++++++++++++++


if __name__ == '__main__':
    logging.basicConfig(filename='info.log', level=logging.INFO)
    """   # initialize the log handler
    logHandler = RotatingFileHandler('info.log', maxBytes=1000, backupCount=1)
    # set the log handler level
    logHandler.setLevel(logging.DEBUG)
    # set the app logger level
    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(logHandler) """
    db_url = 'mysql://root:''@localhost/yaratest'
    
    if not database_exists(DB_URL):
        create_database(DB_URL)
    
    db.init_app(app)
    
    db.create_all()

    app.run(host="0.0.0.0", debug=True)




"""
if __name__ == '__main__':
   # initialize the log handler
    logHandler = RotatingFileHandler('info.log', maxBytes=1000, backupCount=1)
    # set the log handler level
    logHandler.setLevel(logging.INFO)
    # set the app logger level
    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(logHandler)    
    app.run(host="0.0.0.0",port=4000, debug=True)
"""
