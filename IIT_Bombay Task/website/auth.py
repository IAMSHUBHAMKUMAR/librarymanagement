from flask import Blueprint,render_template, request ,flash,redirect,url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from  . import db
import jwt
import json
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth',__name__)

@auth.route('/login',methods=['GET','POST'])
def login():
    if request.method =='POST':
        email = request.form.get('email')
        password = request.form.get('password')
        member_type = request.form.get('member_type')
        login_data = {
            "email": email,
            "password": password,
            "member_type": member_type
        }
        
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                payload = {
                    "payload": login_data
                }
                jwt_token = jwt.encode(payload, "enckey", algorithm = "HS256")
                # return redirect(url_for('views.adminafterlogin'))
                if member_type == "librarian":
                    return render_template("adminafterlogin.html", token_data=jwt_token)
                if member_type == "member":
                    return render_template("studentafter_login.html", token_data=jwt_token)
            else:
                flash('Incorrect password',category='error')
        else:
            flash('Email does not exists', category = 'error')
    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up',methods=['GET','POST'])
def sign_up():
    print("request",request)
    if request.method == 'POST':
        email = request.form.get('email')
        firstname = request.form.get('firstname')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        member_type = request.form.get('member_type')
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists', category='error')
        else:
            if len(email) < 4:
                flash('Email must be greater than 3 characters.',category='error')
            elif len(firstname) <2:
                flash('First Name must be greater than 1 characters.',category='error')
            elif password1 !=password2:
                flash('Password don\'t match.',category='error')
            elif len(password1)<7:
                flash('Password must be at least 7 characters.',category='error')
            else:
                #add user
                new_user = User(email=email, first_name=firstname, password=generate_password_hash(password1, method='sha256'))
                db.session.add(new_user)
                db.session.commit() 
                login_user(user, remember=True)   
                flash('Account Created.',category='success')
                return redirect(url_for('views.login'))
        
    return render_template("sign_up.html", user=current_user)

@auth.route('/delete_account',methods=['POST'])
@login_required
def delete_account():
    enc_data = request.data
    email = enc_data["email"]
    print("email",email)
    user = User.query.filter_by(email=email).first()
    if user:
            db.session.delete(user)
            db.session.commit()
    return redirect(url_for('auth.login'))
