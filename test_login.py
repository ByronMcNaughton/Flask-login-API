import json
import flask_unittest
from app import create_app
from app import db
from app.models import User

''' Class to test all things login'''
class UserAPITests(flask_unittest.ClientTestCase):
    app = create_app()

    def test_login(self, client):
        ''' Testing successful login'''

        payload = {
            "username":"testuser",
            "password":"tempPassword"
        }

        res = client.post(
            '/login', data=json.dumps(payload), 
            content_type="application/json")

        self.assertEqual(res.status_code, 200)


    def test_incorrect_password(self, client):
        ''' Testing incorrect password'''
        payload = {
            "username":"testuser",
            "password":"incorrect"
        }

        res = client.post(
            '/login', data=json.dumps(payload), 
            content_type="application/json")

        self.assertEqual(res.status_code, 401)


    def test_incorrect_username(self, client):
        ''' Testing incorrect username'''
        payload = {
            "username":"incorrect",
            "password":"tempPassword"
        }

        res = client.post(
            '/login', data=json.dumps(payload), 
            content_type="application/json")

        self.assertEqual(res.status_code, 401)


    def test_empty_post(self, client):
        ''' Testing missing data'''
        payload = {
        }

        res = client.post(
            '/login', data=json.dumps(payload), 
            content_type="application/json")

        self.assertEqual(res.status_code, 401)

