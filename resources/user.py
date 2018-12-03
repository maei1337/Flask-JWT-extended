from flask_restful import Resource, reqparse
from models.user import UserModel
from flask_jwt_extended import (create_access_token,
                                create_refresh_token,
                                jwt_refresh_token_required,
                                get_jwt_identity,
                                jwt_required,
                                get_raw_jwt
                                )
from werkzeug.security import safe_str_cmp
from blacklist import BLACKLIST

# Wir lagern den PARSER aus, da er überall gebraucht wird
_user_parser = reqparse.RequestParser()
_user_parser.add_argument('username', type=str, required=True, help="This field not left blank")
_user_parser.add_argument('password', type=str, required=True, help="This field not left blank")

# Retrieve User-Details und Delete Users
class User(Resource):
    @classmethod
    def get(cls, user_id):
        user = UserModel.find_by_id(user_id)

        if not user:
            return {'message': 'User not found'}, 404

        return user.json()

    @classmethod
    def delete(cls, user_id):
        user = UserModel.find_by_id(user_id)

        if not user:
            return {'message': 'User with ID: {} not found'.format(user_id)}, 404

        user.delete_from_db()
        return {'message': 'User deleted'}, 200


class UserRegister(Resource):
    def post(self):
        data = _user_parser.parse_args()

        # Nutz die Methode um zu schauen, ob der USER schon vorhanden ist
        if UserModel.find_by_username(data['username']):

            return {'message': 'A user with that username already exist'}, 400

        user = UserModel(**data) # data['username'], data['password']
        user.save_to_db()

        return user.json(), 201


class UserLogin(Resource):
    @classmethod
    def post(cls):
        data = _user_parser.parse_args()
        user = UserModel.find_by_username(data['username'])

        if user and safe_str_cmp(user.password, data['password']):
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(user.id)

            return {'access_token': access_token, 'refresh_token': refresh_token}, 200

        return {'message': 'Invalid credentials'}, 401


class UserLogout(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti'] # JWT ID, a unique identifier for a JWT
        BLACKLIST.add(jti)
        return {'message': 'Successfully logged out'}, 200


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        return {'access_token': new_token}, 200
