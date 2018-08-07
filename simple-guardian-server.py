from flask import Flask, render_template, session, request, redirect, url_for, send_from_directory
import socketio
import eventlet.wsgi
from http_socket_server import HTTPSocketServer
from flask_sqlalchemy import SQLAlchemy

sio = socketio.Server()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.db'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, unique=True, nullable=False)
    email = db.Column(db.Text, unique=True, nullable=False)
    password = db.Column(db.Text, unique=False, nullable=False)


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.Text, unique=True, nullable=False)
    secret = db.Column(db.Text, unique=False, nullable=True)
    config = db.Column(db.Text, unique=False, nullable=False, default="{}")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('devices', lazy=True))


class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    config = db.Column(db.Text, unique=False, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('rules', lazy=True))


@app.route("/api/serviceName")
def get_new_sid():
    return "simple-guardian-server"


@app.route("/register", methods=["GET", "POST"])
def register():

    return send_from_directory('static', 'register.html')


@app.route("/")
def homepage():
    return send_from_directory('static', 'welcome.html')


if __name__ == '__main__':
    db.create_all()
    h_soc = HTTPSocketServer(app)
    app = socketio.Middleware(sio, app)
    eventlet.wsgi.server(eventlet.listen(('', 5000)), app)
