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

def generate_token(username):
    expiry = datetime.datetime.utcnow() + config.JWT_ACCESS_TOKEN_EXPIRES
    token = jwt.encode({'user':username, 'exp':expiry}, config.SECRET_KEY)
    return(token)


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
            token = generate_token(user.username)
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
        try:
            token=request.json['token']
        except:
            return jsonify({'msg': 'Token is missing.'}), 403

        if not token:
            return jsonify({'msg': 'Token is missing.'}), 403

        try:
            data=jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"])
        except Exception as e:
            return jsonify({'msg': e}), 403
        
        return f(*args, **kwargs)
    return decorated

@routes.after_request
def refresh_expiring_tokens(response):
    try:
        token=response['token']
        data=jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"])
        exp_timestamp = data["exp"]
        target_expiry = datetime.datetime.utcnow() + config.JWT_ACCESS_TOKEN_EXPIRES
        if target_expiry > exp_timestamp:
            token = generate_token(data['user'])
            response['token'] = token
        return response
    except:
        # Case where there is an error. Just return the original response
        return response

@routes.route('/protected', methods=['POST'])
@token_required
def protected():
    '''
    route only accessible with token
    '''
    return jsonify({'msg': 'Access Granted.'}), 200