from flask_restful import Resource, reqparse
from flask_jwt import jwt_required
from models.store import StoreModel

class Store(Resource):
    #@jwt_required()
    def get(self, name):
        store = StoreModel.find_by_name(name)

        if store:
            return store.json()
        return {'message': 'Store does not exist'}, 404

    #@jwt_required()
    def post(self, name):
        if StoreModel.find_by_name(name):
            return {'message': 'Store {} already exist'.format(name)}, 400

        new_store = StoreModel(name)
        try:
            new_store.save_to_db()
        except:
            return {'message': 'An error occured while creating the store'}, 500

        return new_store.json(), 201

    #@jwt_required()
    def delete(self, name):
        store = StoreModel.find_by_name(name)

        if store is None:
            return {'message': 'Store "{}" does not exist'.format(name)}, 404

        store.delete_from_db()

        return {'message': 'Store {} deleted'.format(name)}


class StoreList(Resource):
    #@jwt_required()
    def get(self):
        return {'stores': [store.json() for store in StoreModel.find_all()]}
