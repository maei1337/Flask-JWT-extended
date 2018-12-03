from flask import Flask
from flask_jwt_extended import JWTManager
from flask_restful import Api

from resources.user import UserRegister, User, UserLogin, TokenRefresh, UserLogout
from resources.item import Item, ItemList
from resources.store import Store, StoreList

from flask import jsonify
from blacklist import BLACKLIST

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLAlCHEMY_TRACK_MODIFICATIONS'] = False
## New
app.config['PROPAGATE_EXCEPTIONS'] = True

### ACHTUNG
app.secret_key = 'matthias' # Das sollte nich öffentlich einsehbar sein
#app.config['JWT_SECRET_KEY'] = 'matthias'

app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

api = Api(app)

@app.before_first_request
def create_tables():
    db.create_all()

### ACHTUNG
jwt = JWTManager(app) # not creating auth endpoint
###
@jwt.user_claims_loader
def add_claims_to_jwt(identity):
    if identity == 1: # should be placed in config file or database
        return {'is_admin': True}
    return {'is_admin': False}

@jwt.token_in_blacklist_loader
def check_token_is_in_checklist(decrypted_token):
    return decrypted_token['jti'] in BLACKLIST

@jwt.expired_token_loader
def expired_token_callback():
    return jsonify({
        'description': 'The token has expired',
        'error': 'token_expired'
    }), 401

# when the token in the header send to us, is no JWT token
@jwt.invalid_token_loader
def invalid_token_callback(error):
        return jsonify({
            'description': 'Signature verification failed.',
            'error': 'Invalid token.'
        }), 401

# When they dont us a empty header, no JWT token was send
@jwt.unauthorized_loader
def missing_token_callback(error):
        return jsonify({
            'description': 'Request does not contain an access token.',
            'error': 'authorization_required.'
        }), 401

# Demand for a new fresh token, but it wasnt send to us
@jwt.needs_fresh_token_loader
def token_not_fresh_callback():
        return jsonify({
            'description': 'The token is not fresh.',
            'error': 'fresh_token_required.'
        }), 401

# The token is no longer available --> like a bann/logout a user --> revoked token list
@jwt.revoked_token_loader
def revoked_token_callback():
        return jsonify({
            'description': 'The token has been removed.',
            'error': 'token_revoked.'
        }), 401

api.add_resource(ItemList, '/items')
api.add_resource(Item, '/item/<string:name>')
api.add_resource(UserRegister, '/register')
api.add_resource(Store, '/store/<string:name>')
api.add_resource(StoreList, '/stores')
api.add_resource(User, '/user/<int:user_id>')
api.add_resource(UserLogin, '/login')
api.add_resource(TokenRefresh, '/refresh')
api.add_resource(UserLogout, '/logout')

#### IMPORT VON DB
if __name__ == '__main__':
    from db import db
    db.init_app(app)
    app.run(port=5000, debug=True)
