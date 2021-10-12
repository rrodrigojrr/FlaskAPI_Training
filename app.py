from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Schema
from flask_restful import Resource, Api
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)
api = Api(app)

class UserModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(25), nullable=False, unique=True)
    password = db.Column(db.String(20), nullable=False)


    def check_rash(self, password):
        return check_password_hash(self.password, password)

class UserSchema(Schema):
    class Meta:
        fields = ['username', 'email']

User_schema = UserSchema()

class UserMethods(Resource):

    def get(self):
        if not request.args:
            return {'Msg' : 'Select an id!'}

        id = request.args['id']
        result = User_schema.dump(
            UserModel.query.filter_by(id=id)
        )

        return jsonify(result)

    def post(self):
        if not request.json:
            return {'Msg': 'Data is missing'}

        username = request.json['username']
        email = request.json['email']
        password = request.json['password']

        user = UserModel(
            username=username,
            email=email,
            password=password
        )

        db.session.add(user)
        db.session.commit()

        return {'Msg' : 'User included!'}

db.create_all()

api.add_resource(UserMethods, '/user')

if __name__ == '__main__':
    app.run(debug=True)

