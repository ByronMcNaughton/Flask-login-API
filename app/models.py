from . import db

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200))
    password_hash = db.Column(db.String(128))
    is_verified = db.Column(db.Boolean)