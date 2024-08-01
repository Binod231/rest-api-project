import os
from flask import jsonify
from flask.views import MethodView
from flask_smorest import Blueprint, abort
from passlib.hash import pbkdf2_sha256      #Hashing algo to use pasword change into unreadable form and comparing incoming password to able in db
from flask_jwt_extended import create_access_token,create_refresh_token,get_jwt_identity,get_jwt, jwt_required  #access_token is combination of nums and chars

import redis
from rq import Queue
from sqlalchemy import or_
from tasks import send_user_registration_email  # noqa: F401

from datetime import datetime
from datetime import timezone

from db import db
from model import UserModel, TokenBlocklist
from schema import UserSchema,UserRegisterSchema

blp = Blueprint("Users", "user", description="Operations on items")

connection = redis.from_url(
    os.getenv("rediss://red-cqll1hg8fa8c73b37qg0:mFOauHW4d3bqgV3Bo8eu5jnJyuErt8SQ@oregon-redis.render.com:6379")
)  # Get this from Render.com or run in Docker
queue = Queue("emails", connection=connection)


@blp.route("/register")
class UserRegister(MethodView):
    @blp.arguments(UserRegisterSchema)
    # @blp.arguments(UserSchema)
    def post(self, user_data):
        if UserModel.query.filter(
            or_(
                UserModel.username == user_data["username"],
                UserModel.email == user_data["email"],
            )
        ).first():
            abort(409, message="A user with that username or email already exists.")
        
        user = UserModel(
            username = user_data["username"],
            email=user_data["email"],
            password = pbkdf2_sha256.hash(user_data["password"])
            )
        db.session.add(user)
        db.session.commit()

        queue.enqueue(send_user_registration_email, user.email, user.username)

    
        return {"message" : "User created Sucessfully. "},201
    

@blp.route("/login")
class UserLogin(MethodView):
    @blp.arguments(UserSchema)
    def post(self, user_data):
        user = UserModel.query.filter(
            UserModel.username == user_data["username"]
        ).first()

        if user and pbkdf2_sha256.verify(user_data["password"],user.password):
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(identity=user.id)
            return {"access_token": access_token, "refresh_token": refresh_token}, 200
        
        abort(
            401,
            message = "Invalid Credential."
        )


@blp.route("/refresh")
class TokenRefresh(MethodView):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        return {"access_token": new_token}

@blp.route("/logout")
class UserLogout(MethodView):
    @jwt_required(verify_type=False)
    def post(self):
        token = get_jwt()
        jti = token["jti"]
        ttype = token["type"]
        now = datetime.now(timezone.utc)
        db.session.add(TokenBlocklist(jti=jti, type=ttype, created_at=now))
        db.session.commit()
        return jsonify(msg=f"{ttype.capitalize()} token successfully revoked")


@blp.route("/user/<int:user_id>")
class User(MethodView):
    @blp.response(200, UserSchema)
    def get(self, user_id):
        user = UserModel.query.get_or_404(user_id)
        return user
    
    def delete(self, user_id):
        user = UserModel.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return {"message": "Deleted Sucessfully. "},201
