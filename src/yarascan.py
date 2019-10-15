import os
import yara
from yararule import db
import flask_sqlalchemy

class YaraScan(db.Model):
    
  id = db.Column(db.Integer, primary_key=True)
  dataToScan = db.Column(db.String(80) , nullable=False)   
  result = db.Column(db.String(500), nullable=False)

  def __init__(self, dataToScan, yaraRules_dict):
    self.dataToScan = dataToScan
    self.yaraRules_dict = yaraRules_dict
    self.resultList = self.scan()
    self.result = str(self.resultList)

  def scan(self):
    result = list()
    
    def mycallback(data):
      parser = {"rule_id":int(data["namespace"]), 
                "matched":data["matches"]}

      result.append(parser)
      return yara.CALLBACK_CONTINUE
    
    if os.path.exists(self.dataToScan):
          data = {'filepath':self.dataToScan}
    else:
          data = {'data':self.dataToScan}
     
    rule = yara.compile(sources=self.yaraRules_dict)
    scan = rule.match(**data, callback=mycallback)

    return result
    