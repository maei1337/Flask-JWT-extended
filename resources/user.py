from flask_restful import Resource, reqparse
from models.user import UserModel

from db import db

class UserRegister(Resource):
    parser = reqparse.RequestParser()

    parser.add_argument('username', type=str, required=True, help="This field not left blank")
    parser.add_argument('password', type=str, required=True, help="This field not left blank")

    def post(self):
        data = UserRegister.parser.parse_args()

        # Nutz die Methode um zu schauen, ob der USER schon vorhanden ist
        if UserModel.find_by_username(data['username']):

            return {'message': 'A user with that username already exist'}, 400

        user = UserModel(**data) # data['username'], data['password']
        user.save_to_db()

        return user.json(), 201

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
