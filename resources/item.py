from flask_restful import Resource, reqparse
from flask_jwt_extended import (jwt_required, get_jwt_claims,
                                jwt_optional, get_jwt_identity, fresh_jwt_required)
from models.item import ItemModel

class Item(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('price', type=float, required=True, help="This field not left blank")

    parser.add_argument('store_id', type=int, required=True, help="Every Item needs a store id")

    #@jwt_required
    def get(self, name):
        item = ItemModel.find_by_name(name)

        if item:
            return item.json()
        return {'message': 'item not found in DB'}, 404

    #@jwt_required
    def post(self, name):
        if ItemModel.find_by_name(name):
            return {'message': 'item already exists in DB'}, 400

        data = Item.parser.parse_args()

        item = ItemModel(name, **data) # (name, data['price'], data['store_id'])

        try:
            item.save_to_db()
        except:
             return {'message': 'An error occured inserting the item'}, 500 # internal SERVER ERROR

        return item.json(), 201

    @fresh_jwt_required
    def delete(self, name):
        claims = get_jwt_claims()
        if not claims['is_admin']:
            return {'message': 'Admin privilege required'}, 401

        deleted_item = ItemModel.find_by_name(name)
        if deleted_item is None:
            return {'message': 'Item "{}" not exist in DB'.format(name)}, 404

        deleted_item.delete_from_db()

        return {'message': 'item deleted'}, 201

    @jwt_required
    def put(self, name):
        data = Item.parser.parse_args()

        item = ItemModel.find_by_name(name)

        if item is None:
            item = ItemModel(name, **data) #(name, data['price'], data['store_id'])
        else:
            item.price = data['price']
            # Man könnte auch STORE ID hier verändern wenn man will!!!

        item.save_to_db()

        return item.json()

class ItemList(Resource):
    @jwt_optional
    def get(self):
        user_id = get_jwt_identity()
        items = [item.json() for item in ItemModel.find_all()]
        if user_id:
            return {'items': items}, 200

        return {'items': [item['name'] for item in items],
                'message': 'More data provided it you are logged in!!'
        }
