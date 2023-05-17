import json
import flask_unittest
from werkzeug.security import generate_password_hash

from app import create_app
from app import db
from app.models import User

''' Class to test all things login'''
class TestAddUser(flask_unittest.ClientTestCase):
    app = create_app()

    def test_add_user(self, client):
        ''' Testing successfully adding user'''

        payload = {
            "username":"testuser123",
            "password":"TempPassword12"
        }

        res = client.post(
            '/add-user', data=json.dumps(payload), 
            content_type="application/json")

        self.assertEqual(res.status_code, 200)


    def test_short_username(self, client):
        ''' Testing short username'''

        payload = {
            "username":"te",
            "password":"TempPassword12"
        }

        res = client.post(
            '/add-user', data=json.dumps(payload), 
            content_type="application/json")

        self.assertEqual(res.status_code, 422)
        self.assertEqual(json.loads(res.data)['msg'], 'Username must be 5 or more characters.')

        # Cleanup
        try:
            User.query.filter_by(username="te").delete()
            db.session.commit()
        except:
            pass


    def test_username_with_space(self, client):
        ''' Testing username with spaces'''

        payload = {
            "username":"test username",
            "password":"TempPassword12"
        }

        res = client.post(
            '/add-user', data=json.dumps(payload), 
            content_type="application/json")

        self.assertEqual(res.status_code, 422)
        self.assertEqual(json.loads(res.data)['msg'], 'Username must not contain spaces.')

        # Cleanup
        try:
            User.query.filter_by(username="test username").delete()
            db.session.commit()
        except:
            pass


    def test_user_exists(self, client):
        '''Test user already exists'''

        payload = {
            "username":"testuser123",
            "password":"TempPassword12"
        }

        res = client.post(
            '/add-user', data=json.dumps(payload), 
            content_type="application/json")

        self.assertEqual(res.status_code, 422)
        self.assertEqual(json.loads(res.data)['msg'], 'Username already exists.')

        # Cleanup
        try:
            User.query.filter_by(username="testuser123").delete()
            db.session.commit()
        except:
            pass

    def test_password_uppercase(self, client):
        '''Test password contain one uppercase character'''
        
        payload = {
            "username":"testuser",
            "password":"temppassword12"
        }

        res = client.post(
            '/add-user', data=json.dumps(payload), 
            content_type="application/json")

        self.assertEqual(res.status_code, 422)
        self.assertEqual(json.loads(res.data)['msg'], 'Password must contain one uppercase character.')

        # Cleanup
        try:
            User.query.filter_by(username="testuser").delete()
            db.session.commit()
        except:
            pass

    def test_password_lowercase(self, client):
        '''Test password contain one lowercase character'''
        
        payload = {
            "username":"testuser",
            "password":"TEMPPASSWORD12"
        }

        res = client.post(
            '/add-user', data=json.dumps(payload), 
            content_type="application/json")

        self.assertEqual(res.status_code, 422)
        self.assertEqual(json.loads(res.data)['msg'], 'Password must contain one lowercase character.')

        # Cleanup
        try:
            User.query.filter_by(username="testuser").delete()
            db.session.commit()
        except:
            pass

    def test_password_digit(self, client):
        '''Test password contain one digit'''
        
        payload = {
            "username":"testuser",
            "password":"TempPassword"
        }

        res = client.post(
            '/add-user', data=json.dumps(payload), 
            content_type="application/json")

        self.assertEqual(res.status_code, 422)
        self.assertEqual(json.loads(res.data)['msg'], 'Password must contain one number.')

        # Cleanup
        try:
            User.query.filter_by(username="testuser").delete()
            db.session.commit()
        except:
            pass

    def test_password_length(self, client):
        '''Test password length'''
        
        payload = {
            "username":"testuser",
            "password":"Temppa1"
        }

        res = client.post(
            '/add-user', data=json.dumps(payload), 
            content_type="application/json")

        self.assertEqual(res.status_code, 422)
        self.assertEqual(json.loads(res.data)['msg'], 'Password must be 8 or more characters.')

        # Cleanup
        try:
            User.query.filter_by(username="testuser").delete()
            db.session.commit()
        except:
            pass

    def test_empty_payload(self, client):
        '''Test empty payload'''
        
        payload = {
           
        }

        res = client.post(
            '/add-user', data=json.dumps(payload), 
            content_type="application/json")

        self.assertEqual(res.status_code, 401)
        self.assertEqual(json.loads(res.data)['msg'], 'Username/Password not provided.')

        # Cleanup
        try:
            User.query.filter_by(username="testuser").delete()
            db.session.commit()
        except:
            pass

        