import uuid

from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from flask_smorest import abort
from passlib.hash import pbkdf2_sha256

from db import items, stores, users

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "admin"
jwt = JWTManager(app)


@jwt.invalid_token_loader
def invalid_token_callback(error):
    return (
        jsonify(
            {"message": "Signature verification failed.", "error": "invalid_token"}
        ),
        401,
    )


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return (
        jsonify({"message": "The token has expired.", "error": "token_expired"}),
        401,
    )


@jwt.unauthorized_loader
def missing_token_callback(error):
    return (
        jsonify(
            {
                "description": "Request does not contain an access token.",
                "error": "authorization_required",
            }
        ),
        401,
    )


@app.post("/register")
def user_register():
    user_data = request.get_json()
    for user in users:
        if user_data.email == user.email:
            return {"message": "User already registered"}, 404

    user_id = uuid.uuid4().hex
    hash_password = pbkdf2_sha256.hash(user_data["password"])
    token = create_access_token(identity=user_id)
    user = {**user_data, "id": user_id, "password": hash_password}
    users.append(user)
    return {"message": "successfully registered", "accesstoken": token}, 201


@app.post("/login")
def user_login():
    user_data = request.get_json()

    for user in users:
        if user_data["email"] == user["email"]:
            if not pbkdf2_sha256.verify(user_data["password"], user["password"]):
                return {"Wrong credentials": "Password is incorrect"}

            token = create_access_token(identity=user["id"])
            return {"message": "logged in successfully", "accesstoken": token}
    return {"User need to registered": "The provided email is not registered"}, 404


@app.get("/store")
@jwt_required()
def get_stores():
    return {"stores": list(stores.values())}


@app.post("/store")
@jwt_required()
def create_store():
    request_data = request.get_json()
    if "name" not in request_data:
        abort(400, message="Bad Request. Ensure 'name' is included in the JSON payload")

    for store in stores.values():
        if request_data["name"] == store["name"]:
            abort(400, message="Store already exists")

    store_id = uuid.uuid4().hex
    new_store = {**request_data, "id": store_id}
    stores[store_id] = new_store
    return new_store, 201


@app.post("/item")
@jwt_required()
def create_item():
    request_data = request.get_json()

    # check if all details are provided
    # if ("price" not in request_data
    #     or "store_id" not in request_data
    #     or "name" not in request_data):
    #     abort(400, message="Bad request. Ensure 'price', 'store_id' and 'name' is provided")

    # check if item already exist
    for item in items.values():
        if (
            item["name"] == request_data["name"]
            and item["store_id"] == request_data["store-id"]
        ):
            abort(400, message="Item already Exists")

    if request_data["store_id"] not in stores:
        abort(404, message=" Store not found")

    item_id = uuid.uuid4().hex
    new_item = {**request_data, "id": item_id}
    items[item_id] = new_item
    return new_item, 201


@app.get("/item")
@jwt_required()
def get_all_items():
    return {"items": list(items.values())}


@app.get("/store/<string:store_id>")
@jwt_required()
def get_store(store_id):
    try:
        return stores[store_id], 200
    except Exception:
        abort(404, message=" Store not found")


@app.get("/item/<string:item_id>")
@jwt_required()
def get_item(item_id):
    if item_id in items:
        return {"item": items[item_id]}, 200

    abort(404, message=" Item not found")


@app.delete("/item/<string:item_id>")
@jwt_required()
def delete_item(item_id):
    if item_id in items:
        del items[item_id]
        return {"message": "Item Deleted"}, 200

    abort(404, message=" Item not found")
