import datetime
from functools import wraps
from os import name
from urllib import response
import uuid
from flask import Flask, jsonify, make_response, redirect,request,render_template, session, url_for
from flask_jwt_extended import get_jwt_identity, jwt_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

app = Flask(__name__)


app.config['SECRET_KEY'] = 'YeMeriKeyHAi'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(80))
    def to_json(self):
        return {
            "id":self.id,
            "name":self.name,
            "email":self.email,
            "hello":"hello"
        }
    
class Books(db.Model):
    b_id = db.Column(db.Integer, primary_key=True)
    b_name = db.Column(db.String(100))
    b_auth = db.Column(db.String(100))
    b_check = db.Column(db.Boolean)

with app.app_context():
    db.create_all()


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        
        token = request.cookies.get('access_token') 

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(email=data['email']).first()
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            print(str(e))  # print exact error in terminal
            return jsonify({'message': 'Something went wrong!'}), 500

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/signin', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        data = request.form
        email = data.get('email')
        _pass = data.get('password')

        user = User.query.filter_by(email=email).first()
        
        if user and user.password == _pass:  # Compare the password directly
            access_token = jwt.encode(
                {'email': email, 'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)},
                app.config['SECRET_KEY'], algorithm="HS256"
            )
            
            if isinstance(access_token, bytes):
                access_token = access_token.decode('utf-8')

            response = make_response(redirect(url_for('dashboard')))
            response.set_cookie('access_token', access_token, httponly=True, secure=False, samesite='Lax')
            return response
        else:
            return render_template('sign_in.html', message="Invalid credentials!")
            
    return render_template('sign_in.html')



@app.route('/signup', methods=["POST", "GET"])
def register():
    if request.method == 'POST':
        data = request.form
        name = data.get('name')
        email = data.get('email')
        _pass = data.get('password')

        # Check if user already exists by email
        user = User.query.filter_by(email=email).first()
    
        if user:
            return {"message": "User already exists, please log in!"}

        new_user = User(name=name, email=email, password=_pass)  # Store password as is
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))  # Redirect to login page after successful registration
    
    return render_template('sign_up.html')


@app.route('/signout', methods=['POST'])
@token_required
def signout(current_user: User):
    response = make_response(redirect(url_for('login')))  # Redirect to login page after signout
    response.delete_cookie('access_token')  # Delete the access_token cookie to log the user out
    return response



@app.route('/dashboard')
@token_required
def dashboard(current_user:User):
    books=Books.query.all()
    return render_template('dashboard.html',username=current_user.name,email=current_user.email,books=books)

    
#admin section
@app.route('/addbook',methods=['POST'])
@token_required
def add_book(current_user):
    if request.method=="POST":
        data=request.get_json()
        b_name=data['b_name']
        b_auth=data['b_auth']
        print(b_auth)
        exists_book=Books.query.filter_by(b_name=b_name).first()
        if exists_book:
            return {"message":"Book is Already Present!"}
        new_book=Books(b_name=b_name,b_auth=b_auth,b_check=True)
        db.session.add(new_book)
        db.session.commit()   
        return {"message":"A New Book Added SuccesFully!"}
    return {"message":"somthing goes worng!"}

@app.route('/deletebook/<int:b_id>',methods=['DELETE'])
@token_required
def deletebook(current_user,b_id):
    book = Books.query.filter_by(b_id=b_id).first()
    if book:
        db.session.delete(book)
        db.session.commit()
        return {"message": "The Book has been deleted successfully!"}
    else:
        return {"message": "Book not found!"}, 404


@app.route('/updatebook/<int:b_id>',methods=['POST'])
@token_required
def updatebook(current_user,b_id):
    data = request.get_json()
    b_name=data['b_name']
    b_auth=data['b_auth']
    b_check=data['b_check'].lower() == 'true'
    book=Books.query.filter_by(b_id=b_id).first()
    if not book:
        return {"message": "Book not found!"}, 404
    book.b_name=b_name
    book.b_auth=b_auth
    book.b_check=b_check
    db.session.commit()
    return {"message":"Book changes are saved !"}

@app.route('/')
def ho():
    return render_template('sign_up.html')

@app.route('/about')
def about():
    return render_template('about.html')








if __name__=="__main__":
    app.run(debug=True,port=8080)