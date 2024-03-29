import os
from flask import Flask
from flask_restful import Api
from flask_jwt_extended import JWTManager

from resources.user import UserRegister, User, AllUsers, UserLogin, UserLogout, TokenRefresh
from resources.item import Item, ItemList
from resources.store import Store, StoreList
from blacklist import BLACKLIST

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']


app.secret_key = 'tito123'
api = Api(app)


jwt = JWTManager(app)  # /this is not creating auth but initializing jwt extended services


@jwt.user_claims_loader  # this decorator links our claims to JWTManager which in turn links to our app
def add_claims_to_jwt(identity):  # whenever we create a new jwt token we'll run the function to see if we need more data
    if identity == 1:  # instead of hard coding the user.id  1 as the Admin make sure from the DB
        return {'is_admin': True}
    return {'is_admin': False}


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    return decrypted_token['jti'] in BLACKLIST# i.e this is simply saying decrypted token identity in blacklist will be true if its in there and false if not                                                   # if its there its going to go back to the revoked token loader and gives back the error msg token_revoked
                                                #if not in the blacklisr, its going to just continue and allow access


@jwt.expired_token_loader
def expired_token_callback():
    return ({
        'description': "Token has expired",
        'error': 'invalid token'
    }), 401


@jwt.invalid_token_loader
def invalid_token_callback(error):
    return ({
        'description': "signature verification failure",
        'error': 'invalid_token'
    }), 401


@jwt.unauthorized_loader
def missing_token_calback(error):
    return ({
        'description': "Request does not contain an access token",
        'error': "authorization_required"
    }), 401


@jwt.needs_fresh_token_loader
def token_not_fresh_callback():
    return ({
        'description': "Token not fresh",
        'error': "fresh_token_required"
    }), 401


@jwt.revoked_token_loader
def revoked_token_callback():
    return ({
        'description': "Token has been revoked",
        'error': "token_revoked"
    }), 401


api.add_resource(Store, '/store/<string:name>')
api.add_resource(StoreList, '/stores')
api.add_resource(Item, '/item/<string:name>')
api.add_resource(ItemList, '/items')
api.add_resource(UserRegister, '/register')
api.add_resource(User, '/user/<int:user_id>')
api.add_resource(AllUsers, '/users')
api.add_resource(UserLogin, '/login')
api.add_resource(UserLogout, '/logout')
api.add_resource(TokenRefresh, '/refresh')

if __name__ == '__main__':
    from db import db

    db.init_app(app)
    app.run(port=5000, debug=True)
