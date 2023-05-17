import datetime
import json
import flask_unittest
import jwt

import logging



from app import create_app
import config

''' Class to test all things login'''
class TestAddUser(flask_unittest.ClientTestCase):
    app = create_app()

    def test_valid_token(self, client):
        '''
        Testing valid token
        token response should have expiry ~ 30mins in the future
        '''
        
        expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=120)
        token = jwt.encode({'user':'TempUser', 'exp':expiry}, config.SECRET_KEY)

        predicted_refresh_expiery = datetime.datetime.utcnow() + datetime.timedelta(minutes=29)

        payload = {
            "token":token
        }

        res = client.post(
            '/protected', data=json.dumps(payload), 
            content_type="application/json")
        
        res_token = json.loads(res.data)["token"]
        data=jwt.decode(res_token, config.SECRET_KEY, algorithms=["HS256"])
        res_token_exp = data["exp"]
        res_token_exp = datetime.datetime.utcfromtimestamp(res_token_exp)

        # self.assertEqual(res.status_code, 200)
        self.assertGreaterEqual(res_token_exp, predicted_refresh_expiery)