import os
import unittest
from sqlalchemy_utils import create_database, database_exists, drop_database
from app import app, db
from yararule import YaraRule
from yarascan import YaraScan

no_es_coca_rule = {
        "name":"coca",
         "rule":"rule EstoNoEsCocaPapiRule\r\n{\r\n strings:\r\n $my_text_string = \"esto no es coca papi\"\r\n condition:\r\n   $my_text_string\r\n}"}


class TestCase(unittest.TestCase):
    def setUp(self):

        db_url = 'mysql://root:''@localhost/yaratest'
        if not database_exists(db_url):
            create_database(db_url)

        path = os.path.dirname( os.path.realpath(__file__) )
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    

        self.app = app.test_client()
        db.init_app(app)
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        drop_database('mysql://root:''@localhost/yaratest')

        
    def test_agregar_regla_yara(self):
        with app.test_client() as c:
            rv = c.post('/api/rule', json=no_es_coca_rule)
        json_data = rv.get_json()
        coca_rule = YaraRule.query.filter_by(name='coca').first()
        
        assert 'coca' == coca_rule.name

    def test_no_existe_regla(self):
        with app.test_client() as c:
            rv = c.get('/api/rule/7')
        json_data = rv.get_json()
        
        assert   {'Error':'No existe regla para ese Id, ingrese uno nuevo.'} == json_data

    def test_modificar_nombre__regla_yara(self):
        
        with app.test_client() as c:
            rv = c.post('/api/rule', json=no_es_coca_rule)
            data = { "name":"cocacola"}
            rv = c.put('/api/rule/1', json=data)
        json_data = rv.get_json()
        coca_rule = YaraRule.query.filter_by(name='cocacola').first()
        
        assert 'coca' != coca_rule.name
    
    def test_analizar_texto(self):
        with app.test_client() as c:
            rv = c.post('/api/rule', json=no_es_coca_rule)
            data = {"text":"esto es un texto a analizar",
                    "rules":[{"rule_id": 1}]}
            rv = c.post('/api/analyze/text', json=data)
        json_data = rv.get_json()
        
        assert 'False' in json_data['results']




if __name__ == '__main__':
    unittest.main()