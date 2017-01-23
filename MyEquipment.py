import os

from flask import Flask, render_template, redirect, request, url_for, flash,abort
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user,current_user
from flask_migrate import MigrateCommand, Migrate
from flask_script import Manager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import PasswordField, SubmitField, StringField, ValidationError, TextAreaField, DateField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = '@b$p@th'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['DEBUG'] = True
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
@login_required
def index():
    user = current_user._get_current_object()
    if user is None:
        abort(404)
    equipments = user.records.order_by(Record.equipment.desc()).all()
    return render_template('index.html', equipments=equipments)


@app.route('/borrow_equipment', methods=['GET', 'POST'])
@login_required
def borrow():
    return render_template('borrow.html')


@app.route('/return_equipment', methods=['GET', 'POST'])
@login_required
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
            login_user(user)
            return redirect(request.args.get('Next') or url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You've been logged out.")
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(sso=form.sso.data, last_name=form.last_name.data, first_name=form.first_name.data,
                    password=form.password.data, is_active=True, is_admin=False)
        db.session.add(user)
        flash('You can now log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/new_equipment', methods=['GET', 'POST'])
@login_required
def create_equipment():
    form = EquipmentForm()
    if form.validate_on_submit():
        equipment = Equipment(equipment_id=form.equipment_id.data, name=form.name.data, brand=form.brand.data,
                              category=form.category.data, description=form.description.data,
                              equipment_range=form.equipment_range.data, accuracy=form.accuracy.data,
                              status=form.status.data, calibration_due=form.calibration_due.data)
        db.session.add(equipment)
        flash("Equipment has been created successfully.")
        return redirect(url_for('index'))
    return render_template('new_equipment.html', form=form)


# Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    sso = db.Column(db.Integer, primary_key=True)
    last_name = db.Column(db.String(64), nullable=False)
    first_name = db.Column(db.String(64), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    records = db.relationship('Record', backref='user')
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, nullable=True, default=False)

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute')

    @password.setter
    def password(self, pwd):
        self.password_hash = generate_password_hash(pwd)

    def verify_password(self, pwd):
        return check_password_hash(self.password_hash, pwd)

    def get_id(self):
        return self.sso


class Equipment(db.Model):
    __tablename__ = 'equipments'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    equipment_id = db.Column(db.String, nullable=True)
    name = db.Column(db.String, nullable=False)
    brand = db.Column(db.String(64))
    category = db.Column(db.String)
    description = db.Column(db.Text)
    equipment_range = db.Column(db.String)
    accuracy = db.Column(db.String)
    status = db.Column(db.String)
    calibration_due = db.Column(db.Date)


class Record(db.Model):
    __tablename__ = 'records'
    id = db.Column(db.Integer, primary_key=True)
    user_sso = db.Column(db.Integer, db.ForeignKey('users.sso'))
    equipment = db.Column(db.Integer, db.ForeignKey('equipments.id'))
    record_type = db.Column(db.String, nullable=False)


@login_manager.user_loader
def load_user(sso):
    return User.query.get(int(sso))


# Forms
class LoginForm(FlaskForm):
    sso = StringField("SSO:", validators=[DataRequired(), Length(9, 9)])
    pwd = PasswordField("Password:", validators=[DataRequired()])
    # remember_me = BooleanField("Keep me logged in.")
    submit = SubmitField('Log In')


class RegistrationForm(FlaskForm):
    sso = StringField("SSO:", validators=[DataRequired(), Length(9, 9)])
    last_name = StringField('Last Name:', validators=[DataRequired()])
    first_name = StringField('First Name:', validators=[DataRequired()])
    password = PasswordField("Password:",
                             validators=[DataRequired(), EqualTo('password2', message="Password must match.")])
    password2 = PasswordField("Confirm Password:",
                              validators=[DataRequired(), EqualTo('password', message="Password must match.")])

    submit = SubmitField("Register")

    def validate_sso(self, field):
        if User.query.filter_by(sso=field.data).first():
            raise ValidationError("SSO already registered.")


class EquipmentForm(FlaskForm):
    # id = IntegerField('ID:')
    equipment_id = StringField('Equipment ID:', validators=[DataRequired()])
    name = StringField('Name:', validators=[DataRequired()])
    brand = StringField('Brand:', validators=[DataRequired()])
    category = StringField('Category:', validators=[DataRequired()])
    description = TextAreaField('Description:')
    equipment_range = StringField("Range:")
    accuracy = StringField("Accuracy:")
    status = SelectField("Status:", validators=[DataRequired()],
                         choices=[('Available', 'Available'), ('In Use', 'In Use'),
                                  ('In Calibration', 'In Calibration'),
                                  ('Stop Use', 'Stop Use')])
    calibration_due = DateField("Calibration Due Date:")
    submit = SubmitField("Save")


if __name__ == '__main__':
    manager.run()
