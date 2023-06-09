from flask import Flask
import config
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app=Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{config.DB_NAME}'
    db.init_app(app)

    from .routes import routes

    app.register_blueprint(routes, url_prefix='/')

    from .models import User

    with app.app_context():
        db.create_all()

    return app