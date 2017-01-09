import os

from flask import Flask, render_template, redirect, request, url_for, flash
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user
from flask_script import Manager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import PasswordField, BooleanField, SubmitField, StringField
from wtforms.validators import DataRequired, Length
from flask_migrate import MigrateCommand,Migrate

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = '@b$p@th'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
manager = Manager(app)
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)
login_manager = LoginManager(app)
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'


# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/borrow_equipment', methods=['GET', 'POST'])
def borrow():
    return render_template('borrow.html')


@app.route('/return_equipment', methods=['GET', 'POST'])
def return_equipment():
    return render_template('return.html')


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    return render_template('admin.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(sso=form.sso.data).first()
        if user is not None and user.verify_password(form.pwd.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('Next') or url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You've been logged out.")
    return redirect(url_for('index'))


# Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    sso = db.Column(db.Integer, primary_key=True)
    last_name = db.Column(db.String(64), nullable=False)
    first_name = db.Column(db.String(64), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    # records = db.relationship('Record', backref='sso')
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute')

    @password.setter
    def password(self, pwd):
        self.password_hash = generate_password_hash(pwd)

    def verify_password(self, pwd):
        return check_password_hash(self.password_hash, pwd)


class Equipment(db.Model):
    __tablename__ = 'equipments'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    # records = db.relationship('Record', backref='equipment')


class Record(db.Model):
    __tablename__ = 'records'
    id = db.Column(db.Integer, primary_key=True)
    sso = db.Column(db.Integer, db.ForeignKey('users.sso'))
    equipment = db.Column(db.Integer, db.ForeignKey('equipments.id'))
    record_type = db.Column(db.String, nullable=False)


@login_manager.user_loader
def load_user(sso):
    return User.query.get(int(sso))


# Forms
class LoginForm(FlaskForm):
    sso = StringField("SSO:", validators=[DataRequired(), Length(9, 9)])
    pwd = PasswordField("Password:", validators=[DataRequired()])
    remember_me = BooleanField("Keep me logged in.")
    submit = SubmitField('Log In')


if __name__ == '__main__':
    manager.run()