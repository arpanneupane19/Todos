# Written by Arpan Neupane on October 30, 2020
# Copyright ©️ Arpan Neupane 2020.
# Refer to the README.md for more information.

from flask import Flask, url_for, render_template, flash, redirect, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import SubmitField, TextAreaField, StringField, PasswordField, DateTimeField
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
import os
from datetime import datetime
from flask_bcrypt import Bcrypt
import datetime
import time
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

app.config['SECRET_KEY'] = 'jfale!@#gys^&*(@jafd00193n'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.environ.get("EMAIL_TODO")
app.config['MAIL_PASSWORD'] = os.environ.get("PASSWORD_TODO")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def make_session_permanent():
    session.permanent = True

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    todo = db.Column(db.String(130), nullable=False)
    complete = db.Column(db.Boolean)
    due_date = db.Column(db.DateTime)
    todo_time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    todo = db.relationship('Todo', backref='writer', lazy=True)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)],render_kw={"placeholder": "Email Address"})
    username = StringField(validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Password"})

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")
    
    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("That email address belongs to different user. Please choose a different one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


class CreateForm(FlaskForm):
    todo = StringField(validators=[InputRequired(), Length(min=4, max=130)], render_kw={"placeholder": "Enter Todo"})
    time = DateTimeField(validators=[InputRequired()], format='%H:%M:%S', render_kw={"placeholder": "Due by"})

class EditForm(FlaskForm):
    todo = StringField(validators=[InputRequired(), Length(min=4, max=30)], render_kw={"placeholder": "Edit Todo"})

class ForgotPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)],render_kw={"placeholder": "Email Address"})


class ResetPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email Address"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "New Password"})


class UpdateAccountForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email Address"})

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")
    
    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("That email address belongs to different user. Please choose a different one.")




@app.route('/', methods=['GET', "POST"])
@app.route('/home', methods=['GET', "POST"])
@app.route('/sign-up', methods=['GET', "POST"])
def home():
    form = RegisterForm()

    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))        

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account was successfully created! You are able to login now.')
        return redirect(url_for('login'))
    

    return render_template('home.html', form=form)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html')


@app.errorhandler(403)
def page_not_found(e):
    return "<h1>403 You do not have permission to do that.</h1>", 403


@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()


    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect('dashboard')

    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    incomplete_todos = Todo.query.filter_by(writer=current_user, complete=False).all()
    complete_todos = Todo.query.filter_by(writer=current_user, complete=True).all()
    return render_template('dashboard.html', incomplete_todos=incomplete_todos, complete_todos=complete_todos)


@app.route('/my-account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('account.html', form=form, email=current_user.email, username=current_user.username)

@app.route('/new-todo', methods=['GET','POST'])
@login_required
def create_todo():
    form = CreateForm()
    if form.validate_on_submit():
        new_todo = Todo(todo=form.todo.data, writer=current_user, due_date=form.time.data, complete=False)
        db.session.add(new_todo) 
        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template('create_todo.html', form=form)


@app.route('/delete-todo/<int:todo_id>', methods=['GET', 'POST'])
@login_required
def delete_todo(todo_id):
    todo = Todo.query.filter_by(writer=current_user, id=todo_id).first_or_404()
    db.session.delete(todo)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/complete-todo/<int:todo_id>', methods=['GET','POST'])
@login_required
def complete_todo(todo_id):
    todo = Todo.query.filter_by(id=todo_id, writer=current_user).first_or_404()
    todo.complete = True
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/edit-todo/<int:todo_id>', methods=['GET','POST'])
@login_required
def edit_todo(todo_id):
    todo = Todo.query.filter_by(id=todo_id, writer=current_user).first_or_404()
    form = EditForm()
    if form.validate_on_submit():
        todo.todo = form.todo.data
        db.session.commit()
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.todo.data = todo.todo
    return render_template('edit_todo.html', form=form)


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Forgot your password?',
                  sender='todosapp1490@gmail.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
    {url_for('reset_password', token=token, _external=True)}
If you did not make this request then simply ignore this email.
'''
    mail.send(msg)


# If a user forgets their password
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    form = ForgotPasswordForm()
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent to that email address you provided. If this was an accidental request, you can ignore the email.')

    return render_template("forgot_password.html", form=form, title="Forgot Password")


# Reset the Password
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('forgot_password'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', title='Reset Password', form=form)





if __name__ == '__main__':
    app.run(debug=True)