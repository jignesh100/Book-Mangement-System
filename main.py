import datetime
from functools import wraps
import json
from os import name
from tabnanny import check
from urllib import response
import uuid
from flask import Flask, flash, jsonify, make_response, redirect,request,render_template, session, url_for
# from flask_jwt_extended import get_jwt_identity, jwt_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt
import os
from flask import flash
from sqlalchemy import create_engine, ForeignKey, Column, Integer, String, Text
from sqlalchemy.orm import sessionmaker, relationship
from flask_mail import Mail, Message
from sqlalchemy.ext.declarative import declarative_base
app = Flask(__name__)
import datetime


app.config['SECRET_KEY'] = 'YeMeriKeyHAi'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False



# Email config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = '21dit100@charusat.edu.in'
app.config['MAIL_PASSWORD'] = 'XXXX' 

mail = Mail(app)



#-----FILE-----------------------
app.config['UPLOAD_FOLDER'] = 'uploads/pdfs'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'pdf'}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
from sqlalchemy.engine import Engine
from sqlalchemy import event


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



#for the cascading Delete 
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

#---------------DATABASE----------------------#
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


class BookDownloadRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"))
    book_id = db.Column(db.Integer, db.ForeignKey('books.b_id', ondelete="CASCADE"))
    status = db.Column(db.String(20), default='pending')  # pending / approved / rejected
    request_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    user = db.relationship('User', backref=db.backref('requests', cascade='all, delete-orphan', passive_deletes=True))
    book = db.relationship('Books', backref=db.backref('requests', cascade='all, delete-orphan', passive_deletes=True))


class OTPVerification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(70), unique=True)
    otp = db.Column(db.String(6))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    verified = db.Column(db.Boolean, default=False)



with app.app_context():
    db.create_all()



#----------------AUTHENTICATION----------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('access_token') 

        if not token:
            return redirect(url_for('login', session_expired=1))

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(email=data['email']).first()
        except jwt.ExpiredSignatureError:
            return redirect(url_for('login', session_expired=1))
        except jwt.InvalidTokenError:
            return redirect(url_for('login', session_expired=1))
        except Exception as e:
            print(str(e))
            return redirect(url_for('login', session_expired=1))

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
            flash('User LoggedIn Successfully!', 'success')
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
            flash('Invalid Credentials!', 'error')
            return render_template('sign_in.html', message="Invalid credentials!")
       
    return render_template('sign_in.html')


import random

def generate_otp():
    return str(random.randint(100000, 999999))

@app.route('/signup', methods=["POST", "GET"])
def register():
    if request.method == 'POST':
        data = request.form
        name = data.get('name')
        email = data.get('email')
        _pass = data.get('password')
        role = data.get('role')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("User already exists, please log in!", "error")
            return render_template('sign_up.html')

        otp = generate_otp()
        existing_otp = OTPVerification.query.filter_by(email=email).first()
        if existing_otp:
            # Update OTP and timestamp
            existing_otp.otp = otp
            existing_otp.created_at =  datetime.datetime.utcnow()
            existing_otp.verified = False
        else:
            # Create new OTP record
            new_otp = OTPVerification(email=email, otp=otp, created_at=datetime.datetime.utcnow(), verified=False)
            db.session.add(new_otp)
            db.session.commit()

        # Send email
        msg = Message(
            'Verify your email - OTP',
            sender='your_email@gmail.com',
            recipients=[email]
        )
        msg.html = render_template(
            'email.html',
            name=name,
            otp=otp,
            current_year=datetime.datetime.now().year,
            otp_valid_minutes=10,
            logo_url='https://yourdomain.com/static/logo.png',  # or use url_for('static', filename='logo.png')
            website_url='https://yourdomain.com'
        )
        mail.send(msg)

        
        session['temp_user'] = {'name': name, 'email': email, 'password': _pass, 'role': role}
        flash("OTP sent to your email!", "info")
        return redirect(url_for('verify_otp'))

    return render_template('sign_up.html')

@app.route('/verify_otp', methods=["GET", "POST"])
def verify_otp():
    if 'temp_user' not in session:
        return redirect(url_for('register'))

    temp = session['temp_user']
    email = temp['email']

    if request.method == 'POST':
        user_otp = request.form.get('otp')
        otp_entry = OTPVerification.query.filter_by(email=email).first()

        if not otp_entry:
            flash("No OTP record found for this email!", "error")
            return render_template('verify_otp.html')

        # Check if OTP expired (valid for 10 minutes)
        time_diff = datetime.datetime.utcnow() - otp_entry.created_at
        if time_diff.total_seconds() > 600:
            db.session.delete(otp_entry)
            db.session.commit()
            flash("OTP has expired. Please register again.", "error")
            session.pop('temp_user', None)
            return redirect(url_for('register'))

        # Check if OTP matches
        if otp_entry.otp == user_otp:
            new_user = User(name=temp['name'], email=email, password=temp['password'], role=temp['role'])
            db.session.add(new_user)
            db.session.delete(otp_entry)
            db.session.commit()
            session.pop('temp_user', None)
            flash("Email verified and account created successfully!", "success")
            return redirect(url_for('login'))
        else:
            flash("Invalid OTP!", "error")

    return render_template('verify_otp.html' ,email=email)

@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    if 'temp_user' not in session:
        return redirect(url_for('register'))

    temp = session['temp_user']
    email = temp['email']
    name = temp['name']

    # Generate and update OTP
    otp = generate_otp()
    otp_entry = OTPVerification.query.filter_by(email=email).first()
    if otp_entry:
        otp_entry.otp = otp
        otp_entry.created_at = datetime.datetime.utcnow()
        otp_entry.verified = False
    else:
        new_otp = OTPVerification(email=email, otp=otp)
        db.session.add(new_otp)

    db.session.commit()

    # Resend email
    msg = Message('Your New OTP - Book Management', sender='your_email@gmail.com', recipients=[email])
    msg.html = render_template(
        'email.html',
        name=name,
        otp=otp,
        current_year=datetime.datetime.now().year,
        otp_valid_minutes=10,
        logo_url='https://yourdomain.com/static/logo.png',
        website_url='https://yourdomain.com'
    )
    mail.send(msg)

    flash("A new OTP has been sent to your email.", "info")
    return redirect(url_for('verify_otp'))


@app.route('/edit_email', methods=['GET', 'POST'])
def edit_email():
    temp_user = session.get('temp_user')

    if not temp_user:
        flash("Session expired. Please start over.", "error")
        return redirect(url_for('register'))

    if request.method == 'POST':
        new_email = request.form.get('email')
        existing = User.query.filter_by(email=new_email).first()
        if existing:
            flash("Email already registered. Please use another one.", "error")
            return redirect(url_for('edit_email'))

        # Update email in session
        session['temp_user']['email'] = new_email

        # Generate and store new OTP
        otp = generate_otp()
        otp_entry = OTPVerification.query.filter_by(email=new_email).first()

        if otp_entry:
            otp_entry.otp = otp
            otp_entry.created_at = datetime.datetime.utcnow()
            otp_entry.verified = False
        else:
            new_otp = OTPVerification(email=new_email, otp=otp, created_at=datetime.datetime.utcnow(), verified=False)
            db.session.add(new_otp)

        db.session.commit()

        # Send new OTP email
        msg = Message('Verify Your New Email', sender='your_email@gmail.com', recipients=[new_email])
        msg.html = render_template(
            'email.html',
            name=temp_user['name'],
            otp=otp,
            current_year=2023,
            otp_valid_minutes=10
        )
        mail.send(msg)

        flash("Email updated. A new OTP was sent.", "success")
        return redirect(url_for('verify_otp'))

    return render_template('edit_email.html')



@app.route('/signout', methods=['POST'])
@token_required
def signout(current_user: User):
    flash("User Sign Out Successfully!","success")
    response = make_response(redirect(url_for('login')))  # Redirect to login page after signout
    response.delete_cookie('access_token')  # Delete the access_token cookie to log the user out
    return response



@app.route('/dashboard', methods=['GET', 'POST'])
@token_required
def dashboard(current_user: User):
    keyword = ''
    books = Books.query.all()
   
    book_data = []
    for book in books:
        print(book.b_id)
        book_json = book.to_json()

        approval = BookDownloadRequest.query.filter_by(user_id=current_user.id, book_id=book.b_id).first()
        status = approval.status if approval else 'Not Requested'
        book_data.append({
            'book' : book_json,
            'status': status,
        })

    if request.method == 'POST':
        keyword = request.form.get('search_keyword', '').strip().lower()
        if keyword:
            book_data = [
                entry for entry in book_data
                if keyword in entry['book']['b_name'].lower() or
                   keyword in entry['book']['b_auth'].lower() or
                   keyword in entry['book']['b_isbn'].lower()
            ]
    

    return render_template(
        'dashboard.html',
        username=current_user.name,
        email=current_user.email,
        books=books,
        book_data=book_data,
        keyword=keyword
    )

 
#admin section

@app.route('/admin_dashboard')
@token_required
def admin_dashboard(current_user: User):
    books =Books.query.all()
    if current_user.role != 'admin':
        return redirect(url_for('dashboard')) 
    return render_template('admin_dashboard.html',books=books) 


#--------------Button Routes--------------

#TODO Account Admin Approvals
@app.route('/addbook', methods=['GET'])
@token_required
def show_add_book_form(current_user):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    return render_template('add_book.html')

@app.route('/updatebooks', methods=['GET', 'POST'])
@token_required
def update_books_page(current_user):
    #  Only admins may visit
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    keyword = ''
    # ── Handle the search form ─────────────────────
    if request.method == 'POST':
        keyword = request.form.get('search_keyword', '').strip()
        # Search in name, author or ISBN (case-insensitive)
        books = (
            Books.query
            .filter(
                (Books.b_name.ilike(f'%{keyword}%'))    |
                (Books.b_auth.ilike(f'%{keyword}%'))    |
                (Books.b_isbn.ilike(f'%{keyword}%'))
            )
            .all()
        ) if keyword else Books.query.all()
    else:
        books = Books.query.all()

    return render_template(
        'update_book.html',
        books=books,
        keyword=keyword   
    )






#---------------add-revoke-access---------------------
@app.route('/add_revoke')
@token_required
def add_revoke(current_user):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    requests = BookDownloadRequest.query.all()
    return render_template('add_revoke.html',requests=requests)



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
        flash("Book with this ISBN already exists!","error")
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
    flash("The Book is added Successfully!","success")
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
    flash("The Book Deleted Successfully!","success")
  


    return redirect(url_for('update_books_page')) 


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

        # Handle updated PDF file
        if 'pdf_file' in request.files:
            file = request.files['pdf_file']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

                try:
                    file.save(file_path)
                    # Optionally delete the old PDF
                    if book.pdf_filename:
                        old_path = os.path.join(app.config['UPLOAD_FOLDER'], book.pdf_filename)
                        if os.path.exists(old_path):
                            os.remove(old_path)
                    book.pdf_filename = unique_filename
                except Exception as e:
                    print(f"Error saving file: {str(e)}")
                    return render_template('update.html', book=book, error="Error uploading new PDF!")

            elif file and file.filename != '' and not allowed_file(file.filename):
                return render_template('update.html', book=book, error="Only PDF files are allowed!")

        db.session.commit()
        flash("The Book is Successfully Updated!","success")
        return redirect(url_for('update_books_page'))

    return render_template('update.html', book=book)






@app.route('/request_pdf/<int:b_id>', methods=['POST'])
@token_required
def request_pdf(current_user, b_id):
    # Check if request already exists
    existing_request = BookDownloadRequest.query.filter_by(user_id=current_user.id, book_id=b_id).first()
    if existing_request:
        return redirect(url_for('dashboard'))

    new_request = BookDownloadRequest(user_id=current_user.id, book_id=b_id)
    db.session.add(new_request)
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/approve_request/<int:request_id>', methods=['POST'])
@token_required
def approve_request(current_user, request_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    
    req = BookDownloadRequest.query.get_or_404(request_id)
    req.status = 'approved'
    db.session.commit()
    return redirect(url_for('add_revoke'))

@app.route('/reject_request/<int:request_id>', methods=['POST'])
@token_required
def reject_request(current_user, request_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    req = BookDownloadRequest.query.get_or_404(request_id)
    req.status = 'rejected'
    db.session.commit()
    return redirect(url_for('add_revoke'))




#--------Download Book---------#
@app.route('/download_pdf/<int:b_id>')
@token_required
def download_pdf(current_user, b_id):
    book = Books.query.filter_by(b_id=b_id).first()
    if not book or not book.pdf_filename:
        return jsonify({"message": "PDF not found!"}), 404

    # Check approval
    request_record = BookDownloadRequest.query.filter_by(user_id=current_user.id, book_id=b_id).first()
    if not request_record or request_record.status != 'approved':
        flash("Download not approved by admin!", "error")
        return redirect(url_for('dashboard')) 
        
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], book.pdf_filename)
    if not os.path.exists(file_path):
        flash("PDF file not found on server!", "error")
        return redirect(url_for('dashboard'))  
        

    from flask import send_file
    return send_file(file_path, as_attachment=True, download_name=f"{book.b_name}.pdf")


@app.route('/home')
@token_required
def home(current_user):
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('dashboard'))




@app.route('/')
def ho():
    return render_template('sign_up.html')

@app.route('/about')
def about():
    return render_template('about.html')



if __name__=="__main__":
    app.run(debug=True,port=8080)