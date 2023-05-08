from flask import Blueprint,render_template, request,flash,jsonify,redirect,url_for
from flask_login import login_required, current_user
from . import db
import json
views = Blueprint('views',__name__)


@views.route('/')
@login_required
def home():
    if request.method =='POST':      
        return render_template("base.html", user= current_user)
            
    return render_template("login.html")

@views.route('/adminafterlogin')
@login_required
def adminafterlogin():
            
    return render_template("adminafterlogin.html")
            

