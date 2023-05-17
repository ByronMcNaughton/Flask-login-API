import datetime
import json
import flask_unittest
import jwt

from app import create_app
import config

''' Class to test all things login'''
class TestAddUser(flask_unittest.ClientTestCase):
    app = create_app()

    def test_valid_token(self, client):
        ''' Testing valid token'''
        
        expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=30)
        token = jwt.encode({'user':'TempUser', 'exp':expiry}, config.SECRET_KEY)

        payload = {
            "token":token
        }

        res = client.post(
            '/protected', data=json.dumps(payload), 
            content_type="application/json")

        self.assertEqual(res.status_code, 200)

    def test_invalid_token(self, client):
        ''' Testing invalid token'''
        
        expiry = datetime.datetime.utcnow() - datetime.timedelta(seconds=30)
        token = jwt.encode({'user':'TempUser', 'exp':expiry}, config.SECRET_KEY)

        payload = {
            "token":token
        }

        res = client.post(
            '/protected', data=json.dumps(payload), 
            content_type="application/json")

        self.assertEqual(res.status_code, 403)

    def test_missing_token(self, client):
        ''' Testing missing token'''

        payload = {
            "token":''
        }

        res = client.post(
            '/protected', data=json.dumps(payload), 
            content_type="application/json")

        self.assertEqual(res.status_code, 403)

    def test_missing_payload(self, client):
        ''' Testing missing payload'''

        payload = {
        }

        res = client.post(
            '/protected', data=json.dumps(payload), 
            content_type="application/json")

        self.assertEqual(res.status_code, 403)