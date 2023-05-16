from flask import Blueprint, jsonify, request, make_response
from . import db
import config
import jwt
import datetime

routes = Blueprint('routes', __name__)

@routes.route('/login')
def login():
    '''
    route to login / get token
    '''
    auth = request.authorization

    # No login details sent
    if not auth:
        return make_response('No authentication provided', 401, {'WWW_Authenticate' : 'Basic realm="Login Required"'})
    
    user = db.query.filter_by(username=auth.username).first()
    # username not in database
    if not user:
        return make_response('User could not be found', 401, {'WWW_Authenticate' : 'Basic realm="Login Required"'})
    
    # if passwords dont match
    ################################################## Need to sort out hash
    if user.password != auth.password:
        return make_response('Passwords do not match', 401, {'WWW_Authenticate' : 'Basic realm="Login Required"'})
    
    # If user has not verified their account
    if not user.is_verified:
        return make_response('Account not verified', 401, {'WWW_Authenticate' : 'Basic realm="Login Required"'})
    
    # final confirmation and return token
    if user and user.password == auth.password and user.is_verified:
        expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        token = jwt.encode({'user':user.username, 'exp':expiry}, config.SECRET_KEY)
        return make_response('Token Granted', 200)
    
    
    # return error
    return make_response('Something went wrong', 401, {'WWW_Authenticate' : 'Basic realm="Login Required"'})
    

@routes.route('/add-user')
def add_user():
    '''
    route to add user to db
    '''
    pass

@routes.route('/protected')
def protected():
    '''
    route only accessible with token
    '''
    pass