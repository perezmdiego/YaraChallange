import flask_sqlalchemy

db = flask_sqlalchemy.SQLAlchemy()

class YaraRule(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80),  nullable=False)
    rule = db.Column(db.String(500), nullable=False)

    def __init__(self, name, rule):
        self.name = name
        self.rule = rule

    def to_json(self):
        return {'id':self.id,
                'name':self.name,
                'rule':self.rule}
                
    def to_dict(self):
        return {self.name : self.rule}
