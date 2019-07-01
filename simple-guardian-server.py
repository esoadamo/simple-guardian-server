try:
    import json
    import os
    import random
    import shlex
    import time
    import logging
    import sys
    import re

    import bcrypt
    import eventlet.wsgi

    # noinspection PyPackageRequirements
    import socketio

    from uuid import uuid4
    from queue import Queue
    from flask import Flask, render_template, session, request, redirect, url_for, make_response, abort, Response
    from flask_sqlalchemy import SQLAlchemy
    from flask_cors import CORS
    from sqlalchemy.orm import joinedload
    from datetime import datetime
    from threading import Thread

    from http_socket_server import HTTPSocketServer, HSocket
    from easycrypt import AESCipher
finally:
    from the_runner.requirements_updater import RequirementsUpdater

    RequirementsUpdater().auto()

DIR_DATABASES = os.path.abspath('db')  # directory with database and config.json
CONFIG = {  # dictionary with config. Is overwritten by config.json
    'port': 7221,  # port of the web server
    'forceHTTPS': False,  # if set to True, every generated URL if forced to start with https://
    'logFile': None,  # type: None or str  # string is the path to the file in which the logs will be saved
    'logger': None  # type: logging.Logger  # the Logger object that is used by this application to log.
    # Initialized in logging_init()
}

SID_SECRETS = {}  # sid: {secret, mail}, stores login data about clients that are trying to log in
SID_LOGGED_IN = {}  # sid: mail, stores data logged in clients

# initialize all servers
sio = socketio.Server()
app = Flask(__name__)
CORS(app)
hss = HTTPSocketServer(app)

# set basic config and initialize database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # temporary placement, is set to disc file further in code
db = SQLAlchemy(app)


class AppRunning:
    """
    This class signalizes or sets if this program's threads should run or should be terminated
    """
    app_running = [True]

    @staticmethod
    def is_running() -> bool:
        """
        Tests if the program should be running
        :return: True if the program should be running, False if it should terminate itself
        """
        return len(AppRunning.app_running) > 0

    @staticmethod
    def set_running(val: bool):
        """
        Sets if the program should be running
        :param val: True if the program should be running, False if it should terminate itself
        :return: None
        """
        if val:
            AppRunning.app_running.append(True)
        else:
            AppRunning.app_running.clear()

    @staticmethod
    def exit(exit_code):  # type: (int) -> None
        """
        Signalizes all threads to exit and then exists with specified exit code
        :param exit_code:
        :return: NOne
        """
        AppRunning.set_running(False)
        exit(exit_code)

    @staticmethod
    def sleep_while_running(seconds):  # type: (float) -> None
        """
        Performs a sleep operation on calling thread. Sleep is interrupted if the program is supposed to terminate
        :param seconds: how long should the thread sleep
        :return: None
        """
        while AppRunning.is_running() and seconds > 0:
            sleep = min(1.0, seconds)
            time.sleep(sleep)
            seconds -= sleep


class AsyncSio:
    """
    Asynchronously sending SIO events from other threads
    """

    to_send = Queue()  # Queue of dictionaries to send to client. Filled by using .emit()

    @staticmethod
    def init() -> None:
        """
        Initializes the server by launching the background task
        :return: None
        """
        sio.start_background_task(AsyncSio._background_task)

    @staticmethod
    def _background_task():
        """
        While the application is running, fetches new messages from the to_send Queue and emits them to clients
        :return: None
        """
        while AppRunning.is_running():
            eventlet.sleep(1)
            while not AsyncSio.to_send.empty():
                el = AsyncSio.to_send.get()
                sio.emit(el['event'], el['data'], room=el['room'])

    @staticmethod
    def emit(event, data=None, room=None) -> None:
        """
        Allow us to send async sio emits
        :param event: name of event to emit
        :param data: which data to send
        :param room: and to whom to send it
        :return: None
        """
        AsyncSio.to_send.put({'event': event, 'data': data, 'room': room})


class LoginException(Exception):
    pass


"""
Initialize the database schema
"""

# noinspection PyUnresolvedReferences
association_table_user_profile_likes = db.Table('users-profiles_likes', db.Model.metadata,
                                                db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
                                                db.Column('profile_id', db.Integer, db.ForeignKey('profile.id'))
                                                )

# noinspection PyUnresolvedReferences
association_table_device_profile = db.Table('device-profile', db.Model.metadata,
                                            db.Column('device_id', db.Integer, db.ForeignKey('device.id')),
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

    def delete(self):
        self.__class__.query.filter_by(id=self.id).delete()


# noinspection PyUnresolvedReferences
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mail = db.Column(db.Text, unique=True, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    password = db.Column(db.Text, unique=False, nullable=False)

    def delete(self):  # type: () -> None
        """
        Deletes this device and all his/her data from the database
        :return: None
        """
        [[item.delete() for item in items] for items in [self.devices, self.profiles]]
        self.__class__.query.filter_by(id=self.id).delete()

    @staticmethod
    def login(mail, password):  # type: (str, str) -> None
        """
        Tries to verify the user's mail and password with the database and if verification is successful,
        then saves his session
        :param mail: user's mail
        :param password:  user's password
        :raise LoginException: when the combination of mail and password is unknown to the database
        :return: None if login was successful, if something was wrong then it raises the LoginException
        """
        user = User.query.filter_by(mail=mail).first()
        if user is None:
            raise LoginException('this user does not exist')
        if not bcrypt.checkpw(password, user.password):
            raise LoginException('this combination of user and password is unknown to me')
        session.permanent = True
        session['mail'] = mail

    @staticmethod
    def does_need_login():  # type: () -> False or "Redirect"
        """
        Checks if web user has to log in or is already logged in
        :return: False if user is logged in or Flask's redirect to the login page if the user is not logged in yet
        """
        if 'mail' in session and User.query.filter_by(mail=session['mail']).first() is not None:
            return False
        return redirect(url_for('login'))

    @staticmethod
    def list_sids_by_mail(user_mail):  # type: (str) -> List[str]
        """
        Lists all web user's socket IDs that are logged in and belongs to specific mail
        :param user_mail: mail of the user to checks for SIDs of him
        :return: list of currently active SIDs assigned to specified user
        """
        sids = []
        if user_mail in SID_LOGGED_IN.values():
            for sid, mail in SID_LOGGED_IN.items():
                if mail == user_mail:
                    sids.append(sid)
        return sids

    @staticmethod
    def is_online_by_mail(user_mail: str) -> bool:
        """
        Checks if user is currently online by looking if his mail is assigned to any active web UI's SID
        :param user_mail:  mail of the user to checks for SIDs of him
        :return: True if at least one SID is assigned to this mail, false otherwise
        """
        return user_mail in SID_LOGGED_IN.values()


# noinspection PyUnresolvedReferences
class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.Text, unique=True, nullable=False)
    name = db.Column(db.Text, unique=False, nullable=False)
    secret = db.Column(db.Text, unique=False, nullable=True)
    version = db.Column(db.Text, unique=False, nullable=True, default="0.0")
    profiles = db.relationship("Profile", secondary=association_table_device_profile)
    installed = db.Column(db.Boolean, nullable=False, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('devices', lazy=True))

    @property
    def config(self):  # type: () -> str
        """
        Get JSON file profile for the simple guardian client with online configuration
        :return: content of the JSON profile file
        """
        data = {}
        [data.update(json.loads(profile.config)) for profile in self.profiles]
        return json.dumps(data)

    def is_online(self) -> bool:
        """
        Check if connection between the device and the server is active
        :return: True if connection between the device and the server is active, False otherwise
        """
        return self.id in HSSOperator.sid_device_id_link.values()

    def get_sid(self) -> str or None:
        """
        Gets the SID of this device
        :return: SID if device is connected to this server, None if connection with this server is not estabilished
        """
        vals = HSSOperator.sid_device_id_link.values()
        if self.id not in vals:
            return None
        return list(HSSOperator.sid_device_id_link.keys())[list(vals).index(self.id)]

    def delete(self):  # type: () -> None
        """
        Deletes this device and all cached attacks and bans linked with this device
        :return: None
        """
        [[item.delete() for item in items] for items in [self.attacks, self.bans]]
        self.__class__.query.filter_by(id=self.id).delete()

    @staticmethod
    @sio.on('listDevices')
    def list_for_user(sid, asynchronous=False):  # type: (str, bool) -> None
        """
        Lists devices for the user online on web UI
        :param sid: SID of the user on the web UI the list of devices will be send to
        :param asynchronous: True if you are not calling this function from Flask thread
        :return: None
        """
        if sid not in SID_LOGGED_IN:
            return
        # emit dict of device names and uids
        f_emit = sio.emit if not asynchronous else AsyncSio.emit
        f_emit('deviceList',
               {device.uid: {'name': device.name, 'installed': device.installed,
                             'online': False if not device.installed else device.is_online()} for device in
                User.query.filter_by(mail=SID_LOGGED_IN[sid]).options(
                    joinedload('devices')).first().devices}, room=sid)

    @staticmethod
    @sio.on('deviceNew')
    def create_new(sid, device_name):  # type: (str, str) -> None
        """
        Creates new device and lists client all his devices
        :param sid: SID of the user on the web UI the list of devices will be send to
        :param device_name: name of the new device
        :return: None
        """
        if sid not in SID_LOGGED_IN:
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
    def device_delete(sid, device_id):  # type: (str, int) -> None
        """
        Deletes the device and lists client all his left devices
        :param sid: SID of the user on the web UI the list of devices will be send to
        :param device_id: id of the device to be deleted
        :return: None
        """
        if sid not in SID_LOGGED_IN:
            return
        Device.query.filter_by(uid=device_id, user=User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()).delete()
        db.session.commit()
        Device.list_for_user(sid)


class Attack(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.Integer, unique=True, nullable=True)
    profile = db.Column(db.Text, unique=False, nullable=True)
    user = db.Column(db.Text, unique=False, nullable=True)
    ip = db.Column(db.Text, unique=False, nullable=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    device = db.relationship('Device', backref=db.backref('attacks', lazy=True))

    def delete(self):
        self.__class__.query.filter_by(id=self.id).delete()


class Ban(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.Integer, unique=False, nullable=True)
    ip = db.Column(db.Text, unique=False, nullable=True)
    attacks_count = db.Column(db.Integer, unique=False, nullable=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    device = db.relationship('Device', backref=db.backref('bans', lazy=True))

    def delete(self):
        self.__class__.query.filter_by(id=self.id).delete()


class UserSecret:
    def __init__(self, secret_key):  # type: (str) -> None
        self.__cypher = AESCipher(secret_key)

    def make(self, user):  # type: (str) -> str
        return self.__cypher.encrypt(json.dumps({'user': user}))

    def parse_user(self, secret):  # type: (str) -> str or None
        try:
            user_data_string = self.__cypher.decrypt(secret)
        except ValueError:
            return None
        if not len(user_data_string):
            return None
        return json.loads(user_data_string)['user']


@app.route("/api/serviceName")
def get_service_name():  # type: () -> str
    """
    Used by client when pairing to verify that he has connected to right device
    :return: name of this service
    """
    return "simple-guardian-server"


def init_api():
    # noinspection PyTypeChecker
    user_secret = UserSecret(CONFIG["app_secret"])

    def make_respond(message, status='ok'):
        return Response(json.dumps({'status': status, 'message': message}), mimetype='application/json')

    def get_user():  # type: () -> User or Response
        """
        Parses the user from sg-auth header
        :return: If user sent no or invalid header then response for him to login is returned. Otherwise is returned his
        mail parsed from the header
        """
        need_login_response = make_respond('login required', status='needsLogin')
        if 'sg-auth' not in request.headers:
            return need_login_response
        user_mail = user_secret.parse_user(request.headers['sg-auth'])
        user = User.query.filter_by(mail=user_mail).first()
        return user if user is not None else need_login_response

    @app.route("/api/user/whoami")
    def api_user_whoami():
        user = get_user()
        if type(user) == Response:
            return user
        return make_respond({'username': user.mail, 'id': user.id})

    @app.route("/api/device/list")
    def api_device_list():
        user = get_user()
        if type(user) == Response:
            return user
        return make_respond([{'name': device.name, 'id': device.uid,
                              'status': 'online' if device.is_online()
                              else 'offline' if device.installed else 'not-linked'}
                             for device in
                             User.query.filter_by(mail=user.mail).options(
                                 joinedload('devices')).first().devices])

    @app.route("/api/user/login", methods=["POST"])
    def api_user_login():
        mail = request.json.get('mail', '')
        password = request.json.get('password', '').encode('utf8')
        try:
            User.login(mail, password)
            return make_respond({'login': 'ok', 'key': user_secret.make(mail)})
        except LoginException:
            return make_respond({'login': 'failed', 'key': None})

    @app.route("/api/user/delete")
    def api_user_delete():
        user = get_user()
        if type(user) == Response:
            return user

        user.delete()
        db.session.commit()

        return make_respond(True)

    @app.route("/api/user/password/check", methods=["POST"])
    def api_user_password_check():
        user = get_user()
        if type(user) == Response:
            return user

        password = request.json.get('password', '').encode('utf8')

        return make_respond(bcrypt.checkpw(password, user.password))

    @app.route("/api/user/password/change", methods=["POST"])
    def api_user_password_change():
        user = get_user()
        if type(user) == Response:
            return user

        password = request.json.get('password', '').encode('utf8').strip()

        if len(password) == 0:
            return make_respond('No new password supplied', status='error')

        user.password = bcrypt.hashpw(password, bcrypt.gensalt())
        db.session.commit()
        return make_respond('ok')

    @app.route("/api/user/register", methods=["POST"])
    def api_user_register():
        mail = request.json.get('mail', '').strip()
        password = request.json.get('password', '').encode('utf8').strip()

        if len(mail) == 0 or len(password) == 0:
            return make_respond({'register': 'error', 'message': 'You must send both mail and password'})

        if not re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", mail):
            return make_respond({'register': 'error', 'message': 'This mail is not mail'})

        if User.query.filter_by(mail=mail).first() is not None:
            return make_respond({'register': 'error', 'message': 'This user already exists'})

        db.session.add(User(mail=mail, password=bcrypt.hashpw(password, bcrypt.gensalt())))
        db.session.commit()

        return make_respond({'register': 'ok', 'message': 'You are registered now', 'key': user_secret.make(mail)})

    @app.route("/api/hub/list")
    def api_hub_list():
        """
        Lists all hub profiles and returns them
        :return: data about hub profiles in JSON format
        """
        return make_respond(
            [{'name': profile.name, 'likes': len(profile.likes), 'id': profile.id, 'official': profile.official}
             for profile in Profile.query.all()])

    @app.route("/api/hub/profile/-1", methods=['POST'])
    def api_hub_profile_new():
        return api_hub_profile(-1)

    @app.route("/api/hub/profile/<int:profile_id>/send", methods=['POST'])
    def api_hub_profile_send(profile_id):  # type: (int) -> any
        user = get_user()
        if type(user) == Response:
            return user

        profile = Profile.query.filter_by(id=profile_id).first()  # type: Profile
        devices = [Device.query.filter_by(uid=uid, user=user).first() for uid in request.json.get('devices', [])]

        if None in devices:
            return make_respond('This devices does not exist', status='error')

        if profile is None:
            return make_respond('This profile does not exist', status='error')

        for device in devices:
            if profile in device.profiles:
                continue
            device.profiles.append(profile)
            if device.is_online():
                hss.emit(device.get_sid(), 'config', device.config)

        db.session.commit()
        return make_respond('OK')

    @app.route("/api/hub/profile/<int:profile_id>", methods=['GET', 'POST'])
    def api_hub_profile(profile_id):  # type: (int) -> any
        """
        GET: Lists all hub profiles and returns them
        POST: take profile as data param and save it into database and return success message
        :return: data about hub profiles in JSON format
        """
        profile = Profile.query.filter_by(id=profile_id).first()  # type: Profile
        new_profile = False

        if profile is None and profile_id == -1 and request.method == 'POST':
            profile = Profile()
            new_profile = True

        if profile is None:
            return make_respond('This profile does not exist', status='error')

        if request.method == 'GET':
            return make_respond({
                'name': profile.name,
                'id': profile.id,
                'description': profile.description,
                'config': list(json.loads(profile.config).values())[0],
                'author': profile.author.id
            })

        user = get_user()
        if type(user) == Response:
            return user

        if not new_profile and profile.author != user:
            return make_respond('You are not allowed to do that', status='error')

        data = request.json.get('data')

        if data is None:
            return make_respond('You forgot to send profile data', status='error')

        profile.author = user
        profile.updated = datetime.now()
        profile.description = data['description']
        profile.name = data['name']
        profile.config = json.dumps({profile.name: data['config']})

        if new_profile:
            db.session.add(profile)
        db.session.commit()
        return make_respond({'id': profile.id, 'message': 'Profile saved'})

    @app.route("/api/hub/profile/delete", methods=["POST"])
    def api_hub_profile_delete():
        """
        Deletes profile is user is his author
        :return: message about success / fail
        """

        user = get_user()
        if type(user) == Response:
            return user

        profile = Profile.query.filter_by(id=request.json.get('id')).first()  # type: Profile
        if profile is None:
            return make_respond('This profile does not exist', status='error')

        if user != profile.author:
            return make_respond('You do not have permissions to do this', status='error')

        profile.delete()
        db.session.commit()

        return make_respond("Profile deleted")

    @app.route("/api/device/<string:device_uid>/info")
    def api_device_info(device_uid):  # type: (str) -> any
        """
        Fetches info about device
        :return:
        """
        user = get_user()
        if type(user) == Response:
            return user

        device = Device.query.filter_by(uid=device_uid, user=user).first()

        if device is None:
            return make_respond({}, status='error')

        return make_respond({
            'id': device.uid,
            'name': device.name,
            'status': 'online' if device.is_online() else 'offline' if device.installed else 'not-linked',
            'version': device.version,
            'attacks': [
                {
                    'id': attack.id,
                    'ip': attack.ip,
                    'time': attack.time,
                    'user': attack.user,
                    'profile': attack.profile
                } for attack in device.attacks[:300]
            ],
            'bans': [
                {
                    'id': ban.id,
                    'ip': ban.ip,
                    'time': ban.time,
                    'attacksCount': ban.attacks_count
                } for ban in device.bans[:300]
            ],
            'profiles': [profile.id for profile in device.profiles]
        })

    @app.route("/api/device/create", methods=["POST"])
    def api_device_create():
        """
        Creates new device for user
        :return:
        """
        user = get_user()
        if type(user) == Response:
            return user

        device_name = request.json.get('name', '').strip()

        if Device.query.filter_by(name=device_name, user=user).first() is not None:
            return make_respond({'status': 'error', 'message': 'Device with this name already exists'})

        while True:
            device_uid = uuid4().hex
            if Device.query.filter_by(uid=device_uid).first() is None:
                break

        device = Device(name=device_name, uid=device_uid, user=user)
        db.session.add(device)
        db.session.commit()
        return make_respond({'status': 'ok', 'message': 'Device created', 'id': device_uid})

    @app.route("/api/device/update", methods=["POST"])
    def api_device_update():
        """
        Sends request to the user's device to update it
        :return: JSON {success: boolean, message: description}
        """
        user = get_user()
        if type(user) == Response:
            return user

        device_uid = request.json.get('id', '').strip()
        device = Device.query.filter_by(uid=device_uid, user=user).first()

        if device is None:
            return make_respond({'success': False, 'message': 'Device does not exist'})

        device_sid = device.get_sid()
        if device_sid is None:
            return make_respond({'success': False, 'message': 'Device is offline'})

        hss.emit(device_sid, 'update')
        return make_respond({'success': True, 'message': 'Request sent'})

    @app.route("/api/device/delete", methods=["POST"])
    def api_device_delete():
        """
        Deletes user's device. (specified in the "id" POST key)
        :return: JSON {success: boolean, message: description}
        """
        user = get_user()
        if type(user) == Response:
            return user

        device_uid = request.json.get('id', '').strip()
        device = Device.query.filter_by(uid=device_uid, user=user).first()

        if device is None:
            return make_respond({'success': False, 'message': 'Device does not exist'})

        Device.query.filter_by(uid=device_uid, user=user).delete()
        db.session.commit()
        return make_respond({'success': True, 'message': 'Device deleted'})

    @app.route("/api/device/new/<string:user_mail>/<string:device_id>", methods=['GET', 'POST'])
    def api_device_new(user_mail, device_id):  # type: (str, str) -> str
        """
        On GET shows user information that this page is accessible only by using the SG client
        When SG client accesses this page, it gives him login keys and pairs the device with the user's mail
        :param user_mail: mail of user the calling device will be assigned to
        :param device_id: UUID of the device that is pairing
        :return: login data as JSON if device gave us correct information, 404 otherwise
        """
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
        [Device.list_for_user(sid, asynchronous=True) for sid in User.list_sids_by_mail(device.user.mail)]
        return json.dumps({'service': 'simple-guardian',
                           'device_id': device_id, 'device_secret': device.secret, 'server_url': request.host_url})


def init_old_web_ui():
    @app.route("/api/getSidSecret")
    def get_new_sid():  # type: () -> str or "redirect"
        """
        Requests a secret for user's SID. User must be logged in in order to access this page
        so we are sure to who are we giving the secret to SID
        :return: secret for authentication user's socket
        """
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
        """
        Shows control panel to the user
        User must be logged in
        :return: control panel template
        """
        needs_login = User.does_need_login()
        if needs_login:
            return needs_login
        return render_template('main-panel.html', username=session.get('mail', 'undefined'), logged_in=True)

    @app.route('/user', methods=['GET', 'POST'])
    def user_data():
        """
        Shows panel with user config data and allows them to change them
        User must be logged in
        :return: user data template
        """
        needs_login = User.does_need_login()
        if needs_login:
            return needs_login
        message = ""
        if request.method == "POST":
            try:
                user = User.query.filter_by(mail=session['mail']).first()
                if not bcrypt.checkpw(request.form['passCurrent'].encode('utf8'), user.password):
                    message = "current password does not match"
                    raise InterruptedError
                user.password = bcrypt.hashpw(request.form['passNew'].encode('utf8'), bcrypt.gensalt())
                if request.form.get('reallyChangeMail', '') == 'on':
                    new_mail = request.form['mail']
                    if User.query.filter_by(mail=new_mail).first() is not None:
                        message = "user with this mail already exists"
                        raise InterruptedError
                    user.mail = new_mail
                    session['mail'] = new_mail
                db.session.commit()
                message = 'all changed'
            except KeyError:
                message = "missing required fields"
            except InterruptedError:
                pass
        return render_template('user.html', username=session.get('mail', 'undefined'),
                               mail=session.get('mail', 'undefined'), message=message, logged_in=True)

    @app.route('/hub')
    def hub_search():
        """
        Shows profile hub
        :return: main hub page template
        """
        return render_template('profile-hub-search.html', username=session.get('mail', 'undefined'),
                               logged_in=not User.does_need_login())

    @app.route('/hub/<int:profile_number>/send', methods=['GET', 'POST'])
    def hub_send_profile(profile_number):  # type: (int) -> "template"
        """
        GET method: Shows a UI to send profile to user's device
        POST method: Adds the profile to the config of selected devices
        :param profile_number: ID of the profile in database
        :return: GET method returns template UI to select target devices to send config to, POST method saves the config
        """
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
        """
        Shows profile's details or creates a new profile or delete existing profile
        :param profile_number: profile ID to show, -1 is reserved for creating a new profile
        :return: GET: UI to show or edit profile, POST to save changes
        """
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
        """
        Shows user's profiles
        User must be logged it
        :return: user's profiles template
        """
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
        """
        Logs user out
        :return: redirect to homepage
        """
        session.clear()
        return redirect(url_for('homepage'))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """
        GET: shows a form to login
        POST: verifies the combination of mail and password
        :return: redirect to control panel if login was successful, login page if login pages were not right
        """
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
                mail = request.form.get('mail', None)
                if mail is not None:
                    CONFIG['logger'].warn("%s tried to log in as user \"%s\", but failed" % (request.remote_addr, mail))
                error_msg = str(e)
        return render_template('login.html', error_msg=error_msg)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        """
        GET: shows a form to register
        POST: creates a new user in database
        :return: redirect to control panel if registration was successful, registration page if login pages were not
        right
        """
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
        """
        Shows homepage
        :return: homepage template
        """
        logged_in = not User.does_need_login()
        return render_template('welcome.html', logged_in=logged_in, username=session.get('mail', 'undefined'))

    @app.route("/api/<user_mail>/new_device/<device_id>", methods=['GET', 'POST'])
    def login_new_device(user_mail, device_id):  # type: (str, str) -> str
        """
        On GET shows user information that this page is accessible only by using the SG client
        When SG client accesses this page, it gives him login keys and pairs the device with the user's mail
        :param user_mail: mail of user the calling device will be assigned to
        :param device_id: UUID of the device that is pairing
        :return: login data as JSON if device gave us correct information, 404 otherwise
        """
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
        [Device.list_for_user(sid, asynchronous=True) for sid in User.list_sids_by_mail(device.user.mail)]
        return json.dumps({'service': 'simple-guardian',
                           'device_id': device_id, 'device_secret': device.secret, 'server_url': request.host_url})

    @app.route("/api/<user_mail>/new_device/<device_id>/auto")
    def autoinstall_new_device(user_mail, device_id):
        """
        Gives device a Python script which will install the SG client on the device and pair it with the server
        :param user_mail: mail of user the calling device will be assigned to
        :param device_id: UUID of the device that is pairing
        :return: a Python script which will install the SG client on the device and pair it with the server
        """
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
                                                 zip_url="https://github.com/esoadamo/simple-guardian/"
                                                         "archive/master.zip",
                                                 login_key=login_key))
        response.headers['Content-Type'] = 'text/plain'
        return response

    def check_socket_login(sid):  # type: (str) -> bool
        """
        Checks if socket accessing the web interface is verified as logged in user
        :param sid: web client's socket ID
        :return: True if SID is assigned to user in database, False otherwise
        """
        return sid in SID_LOGGED_IN

    @sio.on('connect')
    def client_connected(sid, __):  # type: (str, any) -> None
        """
        When new web client connects, create him a secret and ask him for verification using this secret
        :param sid: new client's socket ID
        :param __: possible data, unused
        :return: None
        """
        SID_SECRETS[sid] = {'secret': uuid4().hex, 'mail': None}
        sio.emit('askForSecret', sid, room=sid)

    @sio.on('disconnect')
    def client_disconnect(sid):  # type: (str) -> None
        """
        When user disconnects, delete him from list of logged in clients and notify his devices
        :param sid: client's socket ID
        :return: None
        """
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
    def login_client_socket(sid, secret):  # type: (str, str) -> None
        """
        Verify that client is logging in with right socket secret and if so, assign this socket to his mail
        :param sid: client's socket ID
        :param secret: secret fo this socket
        :return: None
        """
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
    def list_profiles(sid, filter_str):  # type: (str, str) -> None
        """
        Lists profiles from database based on the filter and emits the list back to the client
        :param sid: client's socket ID
        :param filter_str: the filter applied on the name of searched profiles
        :return: None
        """
        filter_str = "%" + filter_str + "%"
        sio.emit('profilesList',
                 [{'name': profile.name, 'likes': len(profile.likes), 'id': profile.id, 'official': profile.official}
                  for profile in Profile.query.filter(Profile.name.like(filter_str)).all()], room=sid)

    @sio.on('profileLike')
    def update_likes_on_profile(sid, profile_id):  # type: (str, int) -> None
        """
        Likes or dislikes profile (switches the like status)
        :param sid: client's socket ID
        :param profile_id: id of profile that user want to switch of
        :return: None
        """
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
    def get_device_info(sid, data):  # type: (str, dict) -> None
        """
        User selected a device from list.
        If it is not installed yet, send user info about how to install
        If installed and online, ask the device about its statistic and lower device's asking interval to 2 seconds
        :param sid: web user's socket ID
        :param data: data with target device ID
        :return: None
        """
        if not check_socket_login(sid):
            return
        device_id = data.get('deviceId', '')
        server_address = data.get('serverAddress', '')
        user = User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()
        device = Device.query.filter_by(uid=device_id, user=user).first()
        if device is None:
            return
        device_info = {'config': device.config, 'deviceId': device_id, 'installed': device.installed,
                       'name': device.name}
        if not device.installed:
            login_url = '%s/api/%s/new_device/%s' % (server_address, user.mail, device_id)
            device_info.update(
                {'loginKey': '"%s"' % shlex.quote(login_url),
                 'autoinstallUrl': '"%s"' % shlex.quote(login_url + '/auto')})
        sio.emit('deviceInfo', device_info, room=sid)

        user = User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()
        for other_device in user.devices:
            device_sid = other_device.get_sid()
            if device_sid is None:
                continue
            hss.set_asking_timeout(device_sid, 5 if other_device is not device else 2)

    @sio.on('getAttacks')
    def get_device_attacks(sid, data):  # type: (str, dict) -> None
        """
        User asked us to send him list of attacks from the device. Proxy that command.
        :param sid: web user's socket ID
        :param data: data with target device ID
        :return: None
        """
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
    def get_device_bans(sid, data):  # type: (str, dict) -> None
        """
        User asked us to send him list of bans from the device. Proxy that command.
        :param sid: web user's socket ID
        :param data: data with target device ID
        :return: None
        """
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
    def device_unblock(sid, data):  # type: (str, dict) -> None
        """
        User asked us to unblock IP blocked on device. Proxy that command.
        :param sid: web user's socket ID
        :param data: data with target device ID and Ip IP to unblock
        :return: None
        """
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
    def get_device_update_info(sid, device_id):  # type: (str, str) -> None
        """
        User ask us to ask device about it's update status
        :param sid: web user's socket ID
        :param device_id: target device ID
        :return: None
        """
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
    def device_send_update(sid, device_id):  # type: (str, str) -> None
        """
        Signal the device to update to newest release
        :param sid: web user's socket ID
        :param device_id: target device ID
        :return: None
        """
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
    def device_send_beta_update(sid, device_id):  # type: (str, str) -> None
        """
        Signal the device to update to newest version from master branch
        :param sid: web user's socket ID
        :param device_id: target device ID
        :return: None
        """
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
    def config_update(sid, data):  # type: (str, dict) -> None
        """
        User asked us to send and save new config to and for the device.
        :param sid: web user's socket ID
        :param data: data with target device ID and new config
        :return: None
        """
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
    def get_device_attacks(sid, data):  # type: (str, dict) -> None
        """
        User asked us to list attacks on the device. Ask the device to list the attacks.
        :param sid: web user's socket ID
        :param data: data with target device ID
        :return: None
        """
        if not check_socket_login(sid):
            return
        device_id = data.get('deviceId', '')
        user = User.query.filter_by(mail=SID_LOGGED_IN[sid]).first()
        device = Device.query.filter_by(uid=device_id, user=user).first()
        if device is None:
            return
        device_sid = device.get_sid()
        db.session.commit()
        if device_sid is not None:
            hss.emit(device_sid, 'getStatisticInfo', sid)


class HSSOperator:
    sid_device_id_link = {}

    @staticmethod
    def init():
        """
        Initializes HSocket Server listener
        :return: None
        """
        hss.on('login', HSSOperator.login)
        hss.on('disconnect', HSSOperator.disconnect)
        hss.on('attacks', HSSOperator.attacks)
        hss.on('bans', HSSOperator.bans)
        hss.on('update_info', HSSOperator.update_info)
        hss.on('statistic_data', HSSOperator.statistic_data)

    @staticmethod
    def is_logged_in(soc):  # type: (HSocket) -> bool
        """
        Tests if this socket is already logged in
        :param soc: HSocket of the client
        :return: True if this device's socket is already logged in, False otherwise
        """
        return soc.sid in HSSOperator.sid_device_id_link

    @staticmethod
    def attacks(soc, data):  # type: (HSocket, dict) -> None
        """
        Sends info about performed attacks on client to he user on the web
        :param soc: HSocket of the client
        :param data: dictionary
        :return: None
        """
        if not HSSOperator.is_logged_in(soc):
            return
        data = json.loads(data)

        sender = Device.query.filter_by(id=HSSOperator.sid_device_id_link[soc.sid]).first()

        commit_db = False
        for attack in data.get('attacks', []):
            db_attack = Attack.query.filter_by(device=sender, time=attack.get('time'), ip=attack.get('ip')).first()
            if db_attack is not None:
                continue
            db_attack = Attack(device=sender, time=attack.get('time'),
                               ip=attack.get('ip'),
                               profile=attack.get('profile'),
                               user=attack.get('user'))
            db.session.add(db_attack)
            commit_db = True

        if commit_db:
            db.session.commit()

        client_sid = data.get('userSid', '')
        if client_sid not in SID_LOGGED_IN:
            return
        AsyncSio.emit('attacks',
                      {'deviceId': sender.uid,
                       'attacks': data.get('attacks')}, room=client_sid)

    @staticmethod
    def bans(soc, data):  # type: (HSocket, dict) -> None
        """
        Sends info about banned IPs by client to he user on the web
        :param soc: HSocket of the client
        :param data: dictionary
        :return: None
        """
        if not HSSOperator.is_logged_in(soc):
            return
        data = json.loads(data)

        sender = Device.query.filter_by(id=HSSOperator.sid_device_id_link[soc.sid]).first()

        commit_db = False
        for ban in data.get('bans', []):
            db_ban = Ban.query.filter_by(device=sender, time=ban.get('time'), ip=ban.get('ip')).first()
            if db_ban is not None:
                continue
            db_ban = Ban(device=sender, time=ban.get('time'), ip=ban.get('ip'), attacks_count=ban.get('attacksCount'))
            db.session.add(db_ban)
            commit_db = True

        if commit_db:
            db.session.commit()

        client_sid = data.get('userSid', '')
        if client_sid not in SID_LOGGED_IN:
            return
        AsyncSio.emit('bans',
                      {'deviceId': sender.uid,
                       'bans': data.get('bans')}, room=client_sid)

    @staticmethod
    def statistic_data(soc, data):  # type: (HSocket, dict) -> None
        """
        Sends info about number of attacks and bans of client to he user on the web
        :param soc: HSocket of the client
        :param data: dictionary
        :return: None
        """
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
    def update_info(soc, data):  # type: (HSocket, dict) -> None
        """
        Sends info about updates of client to he user on the web
        :param soc: HSocket of the client
        :param data: dictionary
        :return: None
        """
        if not HSSOperator.is_logged_in(soc):
            return
        data = json.loads(data)
        device = Device.query.filter_by(id=HSSOperator.sid_device_id_link[soc.sid]).first()

        version = data.get('versionCurrent', '')
        if device.version != version:
            device.version = version
            db.session.commit()

        client_sid = data.get('userSid', '')
        if client_sid not in SID_LOGGED_IN:
            return
        data.update({'deviceId': device.uid})
        del data['userSid']
        AsyncSio.emit('updateInfo', data, room=client_sid)

    @staticmethod
    def login(soc, data):  # type: (HSocket, dict) -> None
        """
        Accepts login data from device, verifies it and sends user a list of online devices
        :param soc: HSocket of the client
        :param data: dict. uid key - id of the device, secret - login secret
        :return: None
        """
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
        [Device.list_for_user(sid, asynchronous=True) for sid in User.list_sids_by_mail(device.user.mail)]

    @staticmethod
    def disconnect(soc):  # type: (HSocket) -> None
        """
        Fired on device disconnection and notifies user about the disconnection
        :param soc: HSocket of the client
        :return: None
        """
        if soc.sid in HSSOperator.sid_device_id_link:
            device = Device.query.filter_by(id=HSSOperator.sid_device_id_link[soc.sid]).first()
            del HSSOperator.sid_device_id_link[soc.sid]
            if device is not None:
                [Device.list_for_user(sid, asynchronous=True) for sid in User.list_sids_by_mail(device.user.mail)]


class ThreadAskOnlineDevicesForNewAttacks(Thread):
    def run(self):  # type: () -> None
        """
        Periodically asks device about its status to cache it into dabase
        :return:
        """
        while AppRunning.is_running():
            for online_device_sid in HSSOperator.sid_device_id_link.keys():
                hss.emit(online_device_sid, 'getAttacks', {'userSid': None, 'before': None})
                hss.emit(online_device_sid, 'getBans', {'userSid': None, 'before': None})
            AppRunning.sleep_while_running(5 * 60)


def save_db():
    """
    Save the config to the disc
    """
    with open(os.path.join(DIR_DATABASES, 'config.json'), 'w') as f:
        json.dump(CONFIG, f, indent=1)


def init_db():
    """
    Loads config and starts connection to the database
    """
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


def logging_init():
    """
    Initializes the logger and saves it into CONFIG['logger']
    """
    logger = logging.getLogger()  # type: logging.Logger
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)-1s %(message)s', datefmt='%b %d %H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    if CONFIG['logFile'] is not None:
        file_handler = logging.FileHandler(CONFIG['logFile'])
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    class StreamLogger:
        """
        Puts stream from stdout or stderr to main logger
        """

        def __init__(self, level, prefix=''):
            self.level = level
            self.prefix = prefix

        def write(self, msg):
            while msg.endswith('\n'):
                msg = msg[:-1]
            self.level(self.prefix + msg)

    sys.stdout = StreamLogger(logger.debug, 'STDOUT ')
    sys.stderr = StreamLogger(logger.debug, 'STDERR ')

    # noinspection PyTypeChecker
    CONFIG['logger'] = logger


if __name__ == '__main__':
    # Init everything
    init_db()
    logging_init()
    CONFIG['logger'].info('SG server starting')
    HSSOperator.init()
    AsyncSio.init()
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    init_old_web_ui()
    init_api()
    ThreadAskOnlineDevicesForNewAttacks().start()
    eventlet.wsgi.server(eventlet.listen(('', CONFIG['port'])), socketio.Middleware(sio, app), socket_timeout=60)

    # When this is reached, it means that user has stopped the execution of program
    AppRunning.set_running(False)
    hss.close()
