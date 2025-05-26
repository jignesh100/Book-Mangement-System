import datetime
from functools import wraps
from os import name
from tabnanny import check
from urllib import response
import uuid
from flask import Flask, jsonify, make_response, redirect,request,render_template, session, url_for
# from flask_jwt_extended import get_jwt_identity, jwt_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt
import os

app = Flask(__name__)


app.config['SECRET_KEY'] = 'YeMeriKeyHAi'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#-----FILE 
app.config['UPLOAD_FOLDER'] = 'uploads/pdfs'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'pdf'}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(80))
    role = db.Column(db.String(20), default='customer')  # Added role column
    def to_json(self):
        return {
            "id":self.id,
            "name":self.name,
            "email":self.email,
            "role": self.role
        }
    
class Books(db.Model):
    b_id = db.Column(db.Integer, primary_key=True)
    b_name = db.Column(db.String(100))
    b_auth = db.Column(db.String(100))
    b_isbn = db.Column(db.String(20), unique=True)
    b_pub_year = db.Column(db.Integer)
    b_check = db.Column(db.Boolean)
    pdf_filename = db.Column(db.String(255)) 

    def to_json(self):
        return {
            "b_id": self.b_id,
            "b_name": self.b_name,
            "b_auth": self.b_auth,
            "b_isbn": self.b_isbn,
            "b_pub_year": self.b_pub_year,
            "b_check": self.b_check,
            "pdf_filename": self.pdf_filename
        }


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

            response = make_response(redirect(url_for('dashboard' if user.role == 'customer' else 'admin_dashboard')))
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
        role = data.get('role')

        # Check if user already exists by email
        user = User.query.filter_by(email=email).first()
    
        if user:
            return {"message": "User already exists, please log in!"}

        new_user = User(name=name, email=email, password=_pass, role=role)  # Store password as is
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

@app.route('/admin_dashboard')
@token_required
def admin_dashboard(current_user: User):
    books =Books.query.all()
    if current_user.role != 'admin':
        return redirect(url_for('dashboard')) 
    return render_template('admin_dashboard.html',books=books) 


#--------------Button Routes--------------

@app.route('/addbook', methods=['GET'])
@token_required
def show_add_book_form(current_user):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    return render_template('add_book.html')

@app.route('/updatebooks')
@token_required
def update_books_page(current_user):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    books = Books.query.all()
    return render_template('update_book.html', books=books)



@app.route('/addbook', methods=['POST'])
@token_required
def add_book(current_user):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard')) 
    
    b_name = request.form.get('b_name')
    b_auth = request.form.get('b_auth')
    b_isbn = request.form.get('b_isbn')
    b_pub_year = request.form.get('b_pub_year')

   
    existing_book = Books.query.filter_by(b_isbn=b_isbn).first()
    if existing_book:
        return render_template('add_book.html', error="Book with this ISBN already exists!")
    
    # Handle PDF file upload
    pdf_filename = None
    if 'pdf_file' in request.files:
        file = request.files['pdf_file']
        if file and file.filename != '' and allowed_file(file.filename):
            # Create unique filename to avoid conflicts
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            try:
                file.save(file_path)
                pdf_filename = unique_filename
            except Exception as e:
                print(f"Error saving file: {str(e)}")
                return render_template('add_book.html', error="Error uploading PDF file!")
        elif file and file.filename != '' and not allowed_file(file.filename):
            return render_template('add_book.html', error="Only PDF files are allowed!")
        

   
    new_book = Books(b_name=b_name, b_auth=b_auth, b_isbn=b_isbn, b_pub_year=b_pub_year, b_check=True,pdf_filename=pdf_filename)
    db.session.add(new_book)
    db.session.commit()

    return redirect(url_for('admin_dashboard'))  


@app.route('/deletebook/<int:b_id>',methods=['POST'])
@token_required
def delete_book(current_user,b_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    book = Books.query.filter_by(b_id=b_id).first()
    if not book:
        return jsonify({"message": "Book not found!"}), 404
    db.session.delete(book)
    db.session.commit()
    return redirect(url_for('admin_dashboard')) 


@app.route('/updatebook/<int:b_id>', methods=['GET', 'POST'])
@token_required
def update_book(current_user, b_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    book = Books.query.filter_by(b_id=b_id).first()
    if not book:
        return jsonify({"message": "Book not found!"}), 404

    if request.method == 'POST':
        book.b_name = request.form.get('b_name')
        book.b_auth = request.form.get('b_auth')
        book.b_isbn = request.form.get('b_isbn')
        book.b_pub_year = request.form.get('b_pub_year')
        check = request.form.get('availability')
        book.b_check = (check == "YES")
        db.session.commit()
        return redirect(url_for('admin_dashboard'))

    return render_template('update.html', book=book)


#--------Download Book---------#
@app.route('/download_pdf/<int:b_id>')
@token_required
def download_pdf(current_user, b_id):
    book = Books.query.filter_by(b_id=b_id).first()
    if not book or not book.pdf_filename:
        return jsonify({"message": "PDF not found!"}), 404
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], book.pdf_filename)
    if not os.path.exists(file_path):
        return jsonify({"message": "PDF file not found on server!"}), 404
    
    from flask import send_file
    return send_file(file_path, as_attachment=True, download_name=f"{book.b_name}.pdf")


@app.route('/')
def ho():
    return render_template('sign_up.html')

@app.route('/about')
def about():
    return render_template('about.html')








if __name__=="__main__":
    app.run(debug=True,port=8080)