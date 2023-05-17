from flask import Blueprint, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from . import db
from .models import User
from .validate import validateUsername, validatePassword
import config
import jwt
import datetime

routes = Blueprint('routes', __name__)

@routes.route('/login', methods=['POST'])
def login():
    '''
    route to login / get token
    creates a token if user is valid
    '''

    if request.method == 'POST':
        try:
            data = request.json
            username = data['username']
            password = data['password']
        except:
            return jsonify({
                    'msg': 'Username/Password not provided.'
                }), 401
        
        # No login details sent
        if not username or not password:
            return jsonify({
                    'msg': 'Username/Password not provided.'
                }), 401
        
        try:
            user = User.query.filter_by(username=username).first()
        except:
            return jsonify({
                    'msg': 'Internal error.'
                }), 500
        
        # username not in database
        if user is None:
            return jsonify({
                    'msg': 'User could not be found'
                }), 401
        
        # if passwords dont match
        if not check_password_hash(user.password_hash, password):
            return jsonify({
                    'msg': 'Passwords do not match'
                }), 401
        
        # If user has not verified their account
        if not user.is_verified:
            return jsonify({
                    'msg': 'Account not verified'
                }), 401
        
        # final confirmation and return token
        if user and check_password_hash(user.password_hash, password) and user.is_verified:
            expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            token = jwt.encode({'user':user.username, 'exp':expiry}, config.SECRET_KEY)
            return jsonify({'Token':token}), 200
    
    return jsonify({
                    'msg': 'Something went wrong'
                }), 401
    

@routes.route('/add-user', methods=['POST'])
def add_user():
    '''
    route to add user to db
    '''
    if request.method == 'POST':
        try:
            data = request.json
            username = data['username']
            password = data['password']
        except:
            return jsonify({
                    'msg': 'Username/Password not provided.'
                }), 401

    # No login details sent
    if not username or not password:
        return jsonify({
                'msg': 'Username/Password not provided.'
            }), 401
    
    validate_username = validateUsername(username)
    validate_password = validatePassword(password)

    if validate_username == True:
        if validate_password == True:
            # add to db
            try:
                new_user = User(username=username, password_hash=generate_password_hash(password, method='sha256'), is_verified=True)
                db.session.add(new_user)
                db.session.commit()
                return jsonify({
                        'msg': 'Account added'
                }), 200
            except:
                return jsonify({
                        'msg': 'Internal error.'
                    }), 500
        else:
            return validate_password
    else:
        return validate_username
    
# @routes.route('/validate')
# def protected():
#     '''
#     route to validate account
#     Implement if needed
#     '''
#     pass

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token=request.json['token']

        if not token:
            return jsonify({'msg': 'Token is missing.'}), 403

        try:
            data=jwt.decode(token, config.SECRET_KEY)
        except:
            return jsonify({'msg': 'Token is invalid.'}), 403
        
        return f(*args, **kwargs)

@routes.route('/protected')
@token_required
def protected():
    '''
    route only accessible with token
    '''
    return jsonify({'msg': 'Access Granted.'})