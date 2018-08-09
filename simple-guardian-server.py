import json
import os
import random
import shlex
from uuid import uuid4

import bcrypt
import eventlet.wsgi
import socketio
from flask import Flask, render_template, session, request, redirect, url_for, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload

from http_socket_server import HTTPSocketServer

DIR_DATABASES = os.path.abspath('db')
CONFIG = {
    'port': 7221
}

SID_SECRETS = {}  # sid: {secret, mail}
SID_LOGGED_IN = {}  # sid: mail

sio = socketio.Server()
app = Flask(__name__)
hss = HTTPSocketServer(app)
db = SQLAlchemy(app)


class LoginException(Exception):
    pass


# noinspection PyUnresolvedReferences
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mail = db.Column(db.Text, unique=True, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    password = db.Column(db.Text, unique=False, nullable=False)


# noinspection PyUnresolvedReferences
class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.Text, unique=True, nullable=False)
    name = db.Column(db.Text, unique=False, nullable=False)
    secret = db.Column(db.Text, unique=False, nullable=True)
    config = db.Column(db.Text, unique=False, nullable=False, default="{}")
    installed = db.Column(db.Boolean, nullable=False, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('devices', lazy=True))


# noinspection PyUnresolvedReferences
class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    config = db.Column(db.Text, unique=False, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('rules', lazy=True))
    official = db.Column(db.Boolean, nullable=False, default=False)


def login_user(mail, password):
    user = User.query.filter_by(mail=mail).first()
    if user is None:
        raise LoginException('this user does not exist')
    if not bcrypt.checkpw(password, user.password):
        raise LoginException('this combination of user and password is unknown to me')
    session.permanent = True
    session['mail'] = mail


def does_need_login():
    if 'mail' in session and User.query.filter_by(mail=session['mail']).first() is not None:
        return False
    return redirect(url_for('login'))


@app.route("/api/serviceName")
def get_service_name():
    return "simple-guardian-server"


@app.route("/api/getSidSecret")
def get_new_sid():
    needs_login = does_need_login()
    if needs_login:
        return needs_login
    if 'sid' not in request.args:
        return 'who are you?'
    if request.args['sid'] not in SID_SECRETS:
        return 'you are not connected'
    SID_SECRETS[request.args['sid']]['mail'] = session['mail']
    return SID_SECRETS[request.args['sid']]['secret']


@app.route('/control')
def control_panel():
    needs_login = does_need_login()
    if needs_login:
        return needs_login
    return send_from_directory('static', 'main-panel.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('homepage'))


@app.route("/login", methods=["GET", "POST"])
def login():
    error_msg = ""
    if request.method == "POST":

        try:
            try:
                mail = request.form['mail']
                password = request.form['password'].encode('utf8')
                if len(mail) == 0 or len(password) == 0:
                    raise KeyError()
            except KeyError:
                raise LoginException('send mail and password at least')
            login_user(mail, password)
            return redirect(url_for('control_panel'))
        except LoginException as e:
            error_msg = str(e)
    return render_template('login.html', error_msg=error_msg)


@app.route("/register", methods=["GET", "POST"])
def register():
    error_msg = ""
    if request.method == "POST":
        try:
            try:
                mail = request.form['mail']
                password = request.form['password'].encode('utf8')
                if len(mail) == 0 or len(password) == 0:
                    raise KeyError()
            except KeyError:
                raise LoginException('send mail and password at least')

            if User.query.filter_by(mail=mail).first() is not None:
                raise LoginException('this user already exists')
            db.session.add(User(mail=mail, password=bcrypt.hashpw(password, bcrypt.gensalt())))
            db.session.commit()
            login_user(mail, password)
            return redirect(url_for('control_panel'))
        except LoginException as e:
            error_msg = str(e)
    return render_template('register.html', error_msg=error_msg)


@app.route("/")
def homepage():
    return send_from_directory('static', 'welcome.html')


@app.route("/api/<user_mail>/new_device/<device_id>")
def login_new_device(user_mail, device_id):
    user = User.query.filter_by(mail=user_mail).first()
    if user is None:
        abort(404)
    device = Device.query.filter_by(user=user, uid=device_id).first()
    if device is None or device.installed:  # if device is logged in already, we cannot login anymore
        abort(404)
    device.secret = uuid4().hex
    device.installed = True
    db.session.commit()
    return json.dumps({'service': 'simple-guardian',
                       'device_id': device_id, 'device_secret': device.secret, 'server_url': request.host_url})


def check_socket_login(sid):
    return sid in SID_LOGGED_IN


@sio.on('connect')
def client_connected(sid, __):
    SID_SECRETS[sid] = {'secret': uuid4().hex, 'mail': None}
    sio.emit('askForSecret', sid, room=sid)


@sio.on('disconnect')
def client_disconnect(sid):
    if sid in SID_SECRETS:
        del SID_SECRETS[sid]
    else:
        del SID_LOGGED_IN[sid]


@sio.on('login')
def login_client_socket(sid, secret):
    if sid not in SID_SECRETS or SID_SECRETS[sid]['secret'] != secret:
        sio.emit('login', False, room=sid)
        return
    SID_LOGGED_IN[sid] = SID_SECRETS[sid]['mail']
    del SID_SECRETS[sid]
    sio.emit('login', True, room=sid)


@sio.on('listDevices')
def list_devices(sid):
    if not check_socket_login(sid):
        return
    # emit dict of device names and uids
    sio.emit('deviceList', {device.uid: device.name for device in User.query.filter_by(mail=SID_LOGGED_IN[sid]).options(
        joinedload('devices')).first().devices}, room=sid)


@sio.on('deviceNew')
def device_new(sid, device_name):
    if not check_socket_login(sid):
        return
    while True:
        device_uid = uuid4().hex
        if Device.query.filter_by(uid=device_uid).first() is None:
            break
    device = Device(name=device_name, uid=device_uid, user=User.query.filter_by(mail=SID_LOGGED_IN[sid]).first())
    db.session.add(device)
    db.session.commit()
    list_devices(sid)


@sio.on('deviceDelete')
def device_delete(sid, device_id):
    if not check_socket_login(sid):
        return
    Device.query.filter_by(uid=device_id, user=User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()).delete()
    db.session.commit()
    list_devices(sid)


@sio.on('getDeviceInfo')
def get_device_info(sid, data):
    if not check_socket_login(sid):
        return
    device_id = data.get('deviceId', '')
    server_address = data.get('serverAddress', '')
    user = User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()
    device = Device.query.filter_by(uid=device_id, user=user).first()
    if device is None:
        return
    device_info = {'config': device.config, 'deviceId': device_id, 'installed': device.installed}
    if not device.installed:
        login_url = '%s/api/%s/new_device/%s' % (server_address, user.mail, device_id)
        device_info.update(
            {'loginKey': '"%s"' % shlex.quote(login_url), 'autoinstallUrl': '"%s"' % shlex.quote(login_url + '/auto')})
    sio.emit('deviceInfo', device_info, room=sid)


class HSSOperator:
    sid_device_id_link = {}

    @staticmethod
    def init():
        hss.on('login', HSSOperator.login)
        hss.on('disconnect', HSSOperator.disconnect)

    @staticmethod
    def login(soc, data):
        data = json.loads(data)
        if 'uid' not in data and 'secret' not in data:
            soc.emit('login', False)
            return
        device = Device.query.filter_by(uid=data['uid'], secret=data['secret']).first()
        if device is None:
            soc.emit('login', False)
            return
        HSSOperator.sid_device_id_link[soc.sid] = device.id
        soc.emit('login', True)

    @staticmethod
    def disconnect(soc):
        print('disconnected')
        if soc.sid in HSSOperator.sid_device_id_link:
            del HSSOperator.sid_device_id_link[soc.sid]


def save_db():
    with open(os.path.join(DIR_DATABASES, 'config.json'), 'w') as f:
        json.dump(CONFIG, f, indent=1)


def init_db():
    if not os.path.isdir(DIR_DATABASES):
        os.makedirs(DIR_DATABASES)
    file_config = os.path.join(DIR_DATABASES, 'config.json')
    if os.path.isfile(file_config):
        with open(file_config, 'r') as f:
            CONFIG.update(json.load(f))
    else:
        # noinspection PyTypeChecker
        CONFIG['app_secret'] = ''.join([chr(random.randrange(0, 256)) for __ in range(256)])
        save_db()
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///%s' % os.path.join(DIR_DATABASES, 'db.db')
    app.secret_key = CONFIG['app_secret']
    db.create_all()


if __name__ == '__main__':
    init_db()
    HSSOperator.init()
    eventlet.wsgi.server(eventlet.listen(('', 7224)), socketio.Middleware(sio, app))
