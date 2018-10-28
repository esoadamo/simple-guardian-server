import json
import os
import random
import shlex
import time
from uuid import uuid4
from queue import Queue

import bcrypt
import eventlet.wsgi
from flask import Flask, render_template, session, request, redirect, url_for, make_response, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload
from datetime import datetime

# noinspection PyPackageRequirements
import socketio

from http_socket_server import HTTPSocketServer

DIR_DATABASES = os.path.abspath('db')
CONFIG = {
    'port': 7221,
    'forceHTTPS': False
}

SID_SECRETS = {}  # sid: {secret, mail}
SID_LOGGED_IN = {}  # sid: mail

sio = socketio.Server()
app = Flask(__name__)
hss = HTTPSocketServer(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
db = SQLAlchemy(app)


class AppRunning:
    app_running = [True]

    @staticmethod
    def is_running() -> bool:
        return len(AppRunning.app_running) > 0

    @staticmethod
    def set_running(val: bool):
        if val:
            AppRunning.app_running.append(True)
        else:
            AppRunning.app_running.clear()

    @staticmethod
    def sleep_while_running(seconds):
        while AppRunning.is_running() and seconds > 0:
            sleep = min(1, seconds)
            time.sleep(sleep)
            seconds -= sleep


class AsyncSio:
    to_send = Queue()

    @staticmethod
    def init():
        sio.start_background_task(AsyncSio._background_task)

    @staticmethod
    def _background_task():
        while AppRunning.is_running():
            eventlet.sleep(1)
            while not AsyncSio.to_send.empty():
                el = AsyncSio.to_send.get()
                sio.emit(el['event'], el['data'], room=el['room'])

    @staticmethod
    def emit(event, data=None, room=None):
        """
        Allow us to send async sio emits
        :param event: name of event to emit
        :param data: which data to send
        :param room: and to whom to send it
        """
        AsyncSio.to_send.put({'event': event, 'data': data, 'room': room})


class LoginException(Exception):
    pass


# noinspection PyUnresolvedReferences
association_table_user_profile_likes = db.Table('users-profiles_likes', db.Model.metadata,
                                                db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
                                                db.Column('profile_id', db.Integer, db.ForeignKey('profile.id'))
                                                )


# noinspection PyUnresolvedReferences
class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('profiles', lazy=True))
    name = db.Column(db.Text, unique=False, nullable=False)
    description = db.Column(db.Text, unique=False, nullable=False)
    config = db.Column(db.Text, unique=False, nullable=False)
    likes = db.relationship("User", secondary=association_table_user_profile_likes)
    official = db.Column(db.Boolean, nullable=False, default=False)
    updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


# noinspection PyUnresolvedReferences
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mail = db.Column(db.Text, unique=True, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    password = db.Column(db.Text, unique=False, nullable=False)

    @staticmethod
    def login(mail, password):
        user = User.query.filter_by(mail=mail).first()
        if user is None:
            raise LoginException('this user does not exist')
        if not bcrypt.checkpw(password, user.password):
            raise LoginException('this combination of user and password is unknown to me')
        session.permanent = True
        session['mail'] = mail

    @staticmethod
    def does_need_login():
        if 'mail' in session and User.query.filter_by(mail=session['mail']).first() is not None:
            return False
        return redirect(url_for('login'))

    @staticmethod
    def list_sids_by_mail(user_mail: str) -> list:
        sids = []
        if user_mail in SID_LOGGED_IN.values():
            for sid, mail in SID_LOGGED_IN.items():
                if mail == user_mail:
                    sids.append(sid)
        return sids

    @staticmethod
    def is_online_by_mail(user_mail: str) -> bool:
        return user_mail in SID_LOGGED_IN.values()


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

    def is_online(self) -> bool:
        return self.id in HSSOperator.sid_device_id_link.values()

    def get_sid(self) -> list or None:
        vals = HSSOperator.sid_device_id_link.values()
        if self.id not in vals:
            return None
        return list(HSSOperator.sid_device_id_link.keys())[list(vals).index(self.id)]

    @staticmethod
    @sio.on('listDevices')
    def list_for_user(sid, async=False):
        if not check_socket_login(sid):
            return
        # emit dict of device names and uids
        f_emit = sio.emit if not async else AsyncSio.emit
        f_emit('deviceList',
               {device.uid: {'name': device.name, 'installed': device.installed,
                             'online': False if not device.installed else device.is_online()} for device in
                User.query.filter_by(mail=SID_LOGGED_IN[sid]).options(
                    joinedload('devices')).first().devices}, room=sid)

    @staticmethod
    @sio.on('deviceNew')
    def create_new(sid, device_name):
        if not check_socket_login(sid):
            return
        while True:
            device_uid = uuid4().hex
            if Device.query.filter_by(uid=device_uid).first() is None:
                break
        device = Device(name=device_name, uid=device_uid, user=User.query.filter_by(mail=SID_LOGGED_IN[sid]).first())
        db.session.add(device)
        db.session.commit()
        Device.list_for_user(sid)

    @staticmethod
    @sio.on('deviceDelete')
    def device_delete(sid, device_id):
        if not check_socket_login(sid):
            return
        Device.query.filter_by(uid=device_id, user=User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()).delete()
        db.session.commit()
        Device.list_for_user(sid)


@app.route("/api/serviceName")
def get_service_name():
    return "simple-guardian-server"


@app.route("/api/getSidSecret")
def get_new_sid():
    needs_login = User.does_need_login()
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
    needs_login = User.does_need_login()
    if needs_login:
        return needs_login
    return render_template('main-panel.html', username=session.get('mail', 'undefined'), logged_in=True)


@app.route('/user')
def user_data():
    needs_login = User.does_need_login()
    if needs_login:
        return needs_login
    return render_template('user.html', username=session.get('mail', 'undefined'),
                           mail=session.get('mail', 'undefined'), logged_in=True)


@app.route('/hub')
def hub_search():
    return render_template('profile-hub-search.html', username=session.get('mail', 'undefined'),
                           logged_in=not User.does_need_login())


@app.route('/hub/<int:profile_number>/send', methods=['GET', 'POST'])
def hub_send_profile(profile_number):
    needs_login = User.does_need_login()
    if needs_login:
        return needs_login
    profile = Profile.query.filter_by(id=profile_number).first()
    if profile is None:
        return redirect(url_for('hub_search'))
    user = User.query.filter_by(mail=session['mail']).first()

    if request.method == "POST":
        for device in {Device.query.filter_by(id=device_id).first() for device_id in set(request.form.values())}:
            if device is None:
                continue
            config = json.loads(device.config)
            config.update(json.loads(profile.config))
            device.config = json.dumps(config)
            if device.is_online():
                hss.emit(device.get_sid(), 'config', device.config)
        db.session.commit()
        return redirect(url_for('hub_profile', profile_number=profile_number))

    return render_template('profile-hub-send-to-device.html', username=session.get('mail', 'undefined'),
                           logged_in=True, devices=user.devices, profile=profile)


@app.route('/hub/<profile_number>', methods=['GET', 'POST'])
def hub_profile(profile_number: int):
    try:
        profile_number = int(profile_number)
    except ValueError:
        return redirect(url_for('hub_my_profiles'))
    needs_login = User.does_need_login()
    if needs_login and profile_number == -1:
        return needs_login
    if request.method == "POST":
        user = User.query.filter_by(mail=session['mail']).first()

        if profile_number == -1:
            profile = Profile()
            db.session.add(profile)
        else:
            profile = Profile.query.filter_by(id=profile_number).first()
            if profile is None or profile.author != user:
                return redirect(url_for('hub_search'))

        if 'delete' in request.form and profile_number != -1:
            db.session.delete(profile)
            db.session.commit()
            return redirect(url_for('hub_my_profiles'))

        try:
            profile_data = json.loads(request.form.get('profileData', None))
        except json.JSONDecodeError:
            profile_data = None
        if profile_data is None:
            return redirect(url_for('hub_new'))
        # now check if profile data has all required fields
        if not isinstance(profile_data, dict):
            return redirect(url_for('hub_new'))
        if len(profile_data.keys()) != 1:
            return redirect(url_for('hub_new'))
        profile_name = list(profile_data.keys())[0]
        if not isinstance(profile_data[profile_name], dict):
            return redirect(url_for('hub_new'))
        for field in ['logFile', 'filters']:
            if field not in profile_data[profile_name] or len(profile_data[profile_name][field]) == 0:
                return redirect(url_for('hub_new'))
        if 'description' in profile_data[profile_name]:
            description = profile_data[profile_name]['description']
            del profile_data[profile_name]['description']
        else:
            description = ''

        profile.author = user
        profile.description = description
        profile.name = profile_name
        profile.official = user.admin
        profile.config = json.dumps(profile_data)
        profile.updated = datetime.utcnow()
        db.session.commit()
        return redirect(url_for('hub_my_profiles'))
    profile = None if profile_number == -1 else Profile.query.filter_by(id=profile_number).first()
    if profile is None:
        profile_data = {'unnamed': {'description': '', 'filters': [], 'logFile': ''}}
        editable = True
        profile_exists = False
    else:
        profile_data = json.loads(profile.config)
        profile_data[list(profile_data.keys())[0]]['description'] = profile.description
        profile_exists = True
        if needs_login:
            editable = False
        else:
            editable = profile.author == User.query.filter_by(mail=session['mail']).first()
    return render_template('profile-hub-profile.html', username=session.get('mail', 'undefined'),
                           logged_in=not needs_login,
                           profile_data=profile_data,
                           editable=editable,
                           profile_exists=profile_exists)


@app.route('/hub_my')
def hub_my_profiles():
    needs_login = User.does_need_login()
    if needs_login:
        return needs_login
    user = User.query.filter_by(mail=session['mail']).first()
    profiles = user.profiles
    [profile.__setattr__('likes_num', len(profile.likes)) for profile in profiles]
    return render_template('profile-hub-my.html', username=session.get('mail', 'undefined'),
                           logged_in=True, profiles=profiles)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('homepage'))


@app.route("/login", methods=["GET", "POST"])
def login():
    if not User.does_need_login():
        return redirect(url_for('control_panel'))
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
            User.login(mail, password)
            return redirect(url_for('control_panel'))
        except LoginException as e:
            error_msg = str(e)
    return render_template('login.html', error_msg=error_msg)


@app.route("/register", methods=["GET", "POST"])
def register():
    if not User.does_need_login():
        return redirect(url_for('control_panel'))
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
            User.login(mail, password)
            return redirect(url_for('control_panel'))
        except LoginException as e:
            error_msg = str(e)
    return render_template('register.html', error_msg=error_msg)


@app.route("/")
def homepage():
    logged_in = not User.does_need_login()
    return render_template('welcome.html', logged_in=logged_in, username=session.get('mail', 'undefined'))


@app.route("/api/<user_mail>/new_device/<device_id>", methods=['GET', 'POST'])
def login_new_device(user_mail, device_id):
    if request.method == "GET":
        return "this is meant to be run by your simple-guardian-client, not by your web browser. sorry."
    user = User.query.filter_by(mail=user_mail).first()
    if user is None:
        abort(404)
    device = Device.query.filter_by(user=user, uid=device_id).first()
    if device is None or device.installed:  # if device is logged in already, we cannot login anymore
        abort(404)
    device.secret = uuid4().hex
    device.installed = True
    db.session.commit()
    [Device.list_for_user(sid, async=True) for sid in User.list_sids_by_mail(device.user.mail)]
    return json.dumps({'service': 'simple-guardian',
                       'device_id': device_id, 'device_secret': device.secret, 'server_url': request.host_url})


@app.route("/api/<user_mail>/new_device/<device_id>/auto")
def autoinstall_new_device(user_mail, device_id):
    user = User.query.filter_by(mail=user_mail).first()
    if user is None:
        abort(404)
    device = Device.query.filter_by(user=user, uid=device_id).first()
    if device is None or device.installed:  # if device is logged in already, we cannot login anymore
        abort(404)
    login_key = request.base_url[:-5]  # remove /auto
    if not login_key.startswith('https') and CONFIG['forceHTTPS']:
        login_key = login_key.replace('http', 'https', 1)
    response = make_response(render_template('autoinstall.py',
                                             zip_url="https://github.com/esoadamo/simple-guardian/archive/master.zip",
                                             login_key=login_key))
    response.headers['Content-Type'] = 'text/plain'
    return response


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
        user = User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()
        for device in user.devices:
            device_sid = device.get_sid()
            if device_sid is None:
                continue
            hss.set_asking_timeout(device_sid, 15)
        del SID_LOGGED_IN[sid]


@sio.on('login')
def login_client_socket(sid, secret):
    if sid not in SID_SECRETS or SID_SECRETS[sid]['secret'] != secret:
        sio.emit('login', False, room=sid)
        return
    SID_LOGGED_IN[sid] = SID_SECRETS[sid]['mail']
    del SID_SECRETS[sid]
    sio.emit('login', True, room=sid)

    user = User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()
    for device in user.devices:
        device_sid = device.get_sid()
        if device_sid is None:
            continue
        hss.set_asking_timeout(device_sid, 5)


@sio.on('listProfiles')
def list_profiles(sid, filter_str):
    filter_str = "%" + filter_str + "%"
    sio.emit('profilesList',
             [{'name': profile.name, 'likes': len(profile.likes), 'id': profile.id, 'official': profile.official}
              for profile in Profile.query.filter(Profile.name.like(filter_str)).all()], room=sid)


@sio.on('profileLike')
def update_likes_on_profile(sid, profile_id):
    if not check_socket_login(sid):
        return
    user = User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()
    profile = Profile.query.filter_by(id=profile_id).first()
    if profile is None:
        return
    if user in profile.likes:
        profile.likes.remove(user)
    else:
        profile.likes.append(user)
    db.session.commit()
    sio.emit('profileLikeUpdate', len(profile.likes), room=sid)


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
    device_info = {'config': device.config, 'deviceId': device_id, 'installed': device.installed, 'name': device.name}
    if not device.installed:
        login_url = '%s/api/%s/new_device/%s' % (server_address, user.mail, device_id)
        device_info.update(
            {'loginKey': '"%s"' % shlex.quote(login_url), 'autoinstallUrl': '"%s"' % shlex.quote(login_url + '/auto')})
    sio.emit('deviceInfo', device_info, room=sid)

    user = User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()
    for other_device in user.devices:
        device_sid = other_device.get_sid()
        if device_sid is None:
            continue
        hss.set_asking_timeout(device_sid, 5 if other_device is not device else 2)


@sio.on('getAttacks')
def get_device_attacks(sid, data):
    if not check_socket_login(sid):
        return
    device_id = data.get('deviceId', '')
    user = User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()
    device = Device.query.filter_by(uid=device_id, user=user).first()
    if device is None:
        return
    device_sid = device.get_sid()
    if device_sid is not None:
        hss.emit(device_sid, 'getAttacks', {'userSid': sid, 'before': data.get('attacksBefore', 0)})


@sio.on('getBans')
def get_device_bans(sid, data):
    if not check_socket_login(sid):
        return
    device_id = data.get('deviceId', '')
    user = User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()
    device = Device.query.filter_by(uid=device_id, user=user).first()
    if device is None:
        return
    device_sid = device.get_sid()
    if device_sid is not None:
        hss.emit(device_sid, 'getBans', {'userSid': sid, 'before': data.get('bansBefore', 0)})


@sio.on('unblock')
def device_unblock(sid, data):
    if not check_socket_login(sid):
        return
    device_id = data.get('deviceId', '')
    user = User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()
    device = Device.query.filter_by(uid=device_id, user=user).first()
    if device is None:
        return
    device_sid = device.get_sid()
    if device_sid is not None:
        hss.emit(device_sid, 'unblock_ip', data['ip'])


@sio.on('getUpdateInfo')
def get_device_update_info(sid, device_id):
    if not check_socket_login(sid):
        return
    user = User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()
    device = Device.query.filter_by(uid=device_id, user=user).first()
    if device is None:
        return
    device_sid = device.get_sid()
    if device_sid is not None:
        hss.emit(device_sid, 'get_update_information', sid)


@sio.on('update')
def device_send_update(sid, device_id):
    if not check_socket_login(sid):
        return
    user = User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()
    device = Device.query.filter_by(uid=device_id, user=user).first()
    if device is None:
        return
    device_sid = device.get_sid()
    if device_sid is not None:
        hss.emit(device_sid, 'update')


@sio.on('updateMaster')
def device_send_beta_update(sid, device_id):
    if not check_socket_login(sid):
        return
    user = User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()
    device = Device.query.filter_by(uid=device_id, user=user).first()
    if device is None:
        return
    device_sid = device.get_sid()
    if device_sid is not None:
        hss.emit(device_sid, 'update_master')


@sio.on('configUpdate')
def get_device_attacks(sid, data):
    if not check_socket_login(sid):
        return
    device_id = data.get('deviceId', '')
    user = User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()
    device = Device.query.filter_by(uid=device_id, user=user).first()
    if device is None:
        return
    device_sid = device.get_sid()
    device.config = data.get('config', '{}')
    db.session.commit()
    if device_sid is not None:
        hss.emit(device_sid, 'config', device.config)


@sio.on('getDeviceStatistics')
def get_device_attacks(sid, data):
    if not check_socket_login(sid):
        return
    device_id = data.get('deviceId', '')
    user = User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()
    device = Device.query.filter_by(uid=device_id, user=user).first()
    if device is None:
        return
    device_sid = device.get_sid()
    device.config = data.get('config', '{}')
    db.session.commit()
    if device_sid is not None:
        hss.emit(device_sid, 'getStatisticInfo', sid)


class HSSOperator:
    sid_device_id_link = {}

    @staticmethod
    def init():
        hss.on('login', HSSOperator.login)
        hss.on('disconnect', HSSOperator.disconnect)
        hss.on('attacks', HSSOperator.attacks)
        hss.on('bans', HSSOperator.bans)
        hss.on('update_info', HSSOperator.update_info)
        hss.on('statistic_data', HSSOperator.statistic_data)

    @staticmethod
    def is_logged_in(soc):
        return soc.sid in HSSOperator.sid_device_id_link

    @staticmethod
    def attacks(soc, data):
        if not HSSOperator.is_logged_in(soc):
            return
        data = json.loads(data)
        client_sid = data.get('userSid', '')
        if client_sid not in SID_LOGGED_IN:
            return
        AsyncSio.emit('attacks',
                      {'deviceId': Device.query.filter_by(id=HSSOperator.sid_device_id_link[soc.sid]).first().uid,
                       'attacks': data.get('attacks')}, room=client_sid)

    @staticmethod
    def bans(soc, data):
        if not HSSOperator.is_logged_in(soc):
            return
        data = json.loads(data)
        client_sid = data.get('userSid', '')
        if client_sid not in SID_LOGGED_IN:
            return
        AsyncSio.emit('bans',
                      {'deviceId': Device.query.filter_by(id=HSSOperator.sid_device_id_link[soc.sid]).first().uid,
                       'bans': data.get('bans')}, room=client_sid)

    @staticmethod
    def statistic_data(soc, data):
        if not HSSOperator.is_logged_in(soc):
            return
        data = json.loads(data)
        client_sid = data.get('userSid', '')
        if client_sid not in SID_LOGGED_IN:
            return
        AsyncSio.emit('statisticData',
                      {'deviceId': Device.query.filter_by(id=HSSOperator.sid_device_id_link[soc.sid]).first().uid,
                       'statisticData': data.get('data')}, room=client_sid)

    @staticmethod
    def update_info(soc, data):
        if not HSSOperator.is_logged_in(soc):
            return
        data = json.loads(data)
        client_sid = data.get('userSid', '')
        if client_sid not in SID_LOGGED_IN:
            return
        data.update({'deviceId': Device.query.filter_by(id=HSSOperator.sid_device_id_link[soc.sid]).first().uid})
        del data['userSid']
        AsyncSio.emit('updateInfo', data, room=client_sid)

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
        soc.emit('config', device.config)
        soc.set_asking_timeout(5 if User.is_online_by_mail(device.user.mail) else 15)
        [Device.list_for_user(sid, async=True) for sid in User.list_sids_by_mail(device.user.mail)]

    @staticmethod
    def disconnect(soc):
        if soc.sid in HSSOperator.sid_device_id_link:
            device = Device.query.filter_by(id=HSSOperator.sid_device_id_link[soc.sid]).first()
            del HSSOperator.sid_device_id_link[soc.sid]
            if device is not None:
                [Device.list_for_user(sid, async=True) for sid in User.list_sids_by_mail(device.user.mail)]


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
    AsyncSio.init()
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    eventlet.wsgi.server(eventlet.listen(('', CONFIG['port'])), socketio.Middleware(sio, app), socket_timeout=60)
    AppRunning.set_running(False)
    hss.close()
