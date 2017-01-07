import os

from flask import Flask, render_template
from flask_bootstrap import Bootstrap
from flask_script import Manager
from flask_sqlalchemy import SQLAlchemy

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
manager = Manager(app)
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)


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
# class User(db.Model):
#     pass
#
#
# class Equipment(db.Model):
#     pass
#
#
# class Record(db.Model):
#     pass


if __name__ == '__main__':
    manager.run()
