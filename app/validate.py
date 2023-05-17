from flask import jsonify
from . import db
from .models import User


def validateUsername(username):
    if len(username) < 5:
        return jsonify({
                'msg': 'Username must be 5 or more characters.'
            }), 422
    
    if (" " in username):
        return jsonify({
                'msg': 'Username must not contain spaces.'
            }), 422
    try:
        user = User.query.filter_by(username=username).first()
    except:
        return jsonify({
                'msg': 'Internal error.'
            }), 500
    
    if (user is not None):
        return jsonify({
                'msg': 'Username already exists.'
            }), 422

    else:
        return True
    

def validatePassword(password):
    if (not any(x.isupper() for x in password)):
        return jsonify({
                'msg': 'Password must contain one uppercase character.'
            }), 422

    if (not any(x.islower() for x in password)):
        return jsonify({
                'msg': 'Password must contain one lowercase character.'
            }), 422

    if (not any(x.isdigit() for x in password)):
        return jsonify({
                'msg': 'Password must contain one number.'
            }), 422
    
    if len(password) < 8:
        return jsonify({
                'msg': 'Password must be 8 or more characters.'
            }), 422
    
    else:
        return True