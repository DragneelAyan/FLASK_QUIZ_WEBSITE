from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, login_user, logout_user, current_user


auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.front'))
            else:
                flash('Incorrect password!', category='error')
        else:
            flash('Incorrect username!', category='error')
        
    return render_template("login.html", user=current_user)

@auth.route('/logout')
def logout():
    return redirect(url_for('views.home'))

@auth.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists!', category='error')
        elif len(email) < 4:
            flash('Email is too short', category='error')
        elif len(username) < 4:
            flash('Username is too short', category='error')
        elif len(password1) < 8:
            flash('Password is too short', category="error")
        elif password1!= password2:
            flash('Enter correct password', category="error")
        else:
            new_user = User(email=email, username=username, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user=current_user,remember=True)
            flash('Account created!', category="success")
            return redirect(url_for('views.front'))
        
    return render_template("signup.html")