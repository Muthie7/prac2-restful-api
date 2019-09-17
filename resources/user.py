from flask_restful import Resource, reqparse
from werkzeug.security import safe_str_cmp
from models.user import UserModel
from blacklist import BLACKLIST
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, get_jwt_claims,
                                jwt_refresh_token_required,
                                get_jwt_identity,
                                jwt_required, get_raw_jwt
                                )

_user_parser = reqparse.RequestParser()
_user_parser.add_argument('username', type=str, required=True, help="Field cant be blank")
_user_parser.add_argument('password', type=str, required=True, help="Field cant be blank")


class UserRegister(Resource):
    def post(self):
        data = _user_parser.parse_args()
        if UserModel.find_by_username(data['username']):
            return {"message": "A user with that username already exists"}, 400

        user = UserModel(data['username'], data['password'])
        user.save_to_db()

        return {"message": "User created successfully."}, 201


class User(Resource):
    @classmethod
    def get(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if user:
            return user.json()
        return {"message": "User not Found"}, 404

    @jwt_required
    def delete(self, user_id):
        user = UserModel.find_by_id(user_id)
        claims = get_jwt_claims()
        if claims['is_admin']:
            if user:
                user.delete_from_db()
                return {"message": "User deleted"}
            return {"message": "User not Found"}, 404
        return {'message': 'Admin privilege required!'}


class AllUsers(Resource):  # my resource to find all users
    @jwt_required
    def get(self):
        claims = get_jwt_claims()
        if claims['is_admin']:
            return {'users': [user.json() for user in UserModel.find_all()]}
        return {'message': 'Admin privilege required!!.'}, 401


class UserLogin(Resource):
    @classmethod
    def post(cls):
        data = _user_parser.parse_args()  # going to get data from parser
        user = UserModel.find_by_username(data['username'])  # then its going to find the user in the db

        if user and safe_str_cmp(user.password, data[
            'password']):  # this is what the authenticate function used to do i.e check the user exists and match them to the password parsed
            access_token = create_access_token(identity=user.id,
                                               fresh=True)  # then its going to create an access_token part of JWT_Extended, identity= is what the identity() fucntion used to do
            refresh_token = create_refresh_token(user.id)  # then its going to create a REFRESH TOKEN as well
            return {
                       'access_token': access_token,
                       'refresh_token': refresh_token
                   }, 200  # then its going to return them.
        else:
            return {'message': "Invalid credentials"}, 401


class UserLogout(Resource):
    @jwt_required  # require a jwt because without login in you cant hope to really logout
    def post(
            self):  # to logout you just blacklist their login jwt_token making it non usable again,to get a new token they have to login,essentially logging out
        jti = get_raw_jwt()['jti']  # blacklist the id for the token, which is unique for each token i.e the jti(JWT ID)
        BLACKLIST.add(jti)
        return {'message': "Successfully logged out. Login for continued services"}, 200


class TokenRefresh(Resource):  # going to receive the refresh token we created initially
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user,
                                        fresh=False)  # the access toke we will give back is not going to be fresh i.e if its not fresh the credentials might have timed out
        return {'access_token': new_token}, 200
