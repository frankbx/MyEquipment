import os

from flask import Flask, render_template
from flask_bootstrap import Bootstrap
from flask_script import Manager
from flask_sqlalchemy import SQLAlchemy

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
manager = Manager(app)
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)

# Views
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/borrow_equipment')
def borrow():
    return render_template('borrow.html')


@app.route('/return_equipment')
def return_equipment():
    return render_template('return.html')


@app.route('/admin')
def admin():
    return render_template('admin.html')


# Models
class User(db.Model):
    __tablename__ = 'users'
    sso = db.Column(db.Integer, primary_key=True)
    last_name = db.Column(db.String(64), nullable=False)
    first_name = db.Column(db.String(64), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    records = db.relationship('Record', backref='sso')


class Equipment(db.Model):
    __tablename__ = 'equipments'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    records = db.relationship('Record', backref='equipment')


class Record(db.Model):
    __tablename__ = 'records'
    id = db.Column(db.Integer, primary_key=True)
    sso = db.Column(db.Integer, db.ForeignKey('users.sso'))
    equipment = db.Column(db.Integer, db.ForeignKey('equipments.id'))
    record_type = db.Column(db.String, nullable=False)


if __name__ == '__main__':
    manager.run()
