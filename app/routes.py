from flask import Blueprint

routes = Blueprint('routes', __name__)

@routes.route('/login')
def login():
    '''
    route to login / get token
    '''
    pass

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