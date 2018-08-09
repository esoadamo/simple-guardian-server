from uuid import uuid4
from flask import request
import json
from queue import Queue
from threading import Thread


class HTTPSocketServer:
    def __init__(self, flask_app):
        self._listeners = {}
        self._clients = {}

        @flask_app.route("/hsocket/", methods=['GET', 'POST'])
        def handler():
            if 'sid' not in request.args:
                while True:
                    new_sid = uuid4().hex
                    if new_sid not in self._clients:
                        break
                self._clients[new_sid] = {'queue': Queue(), 'socket': HSocket(self, new_sid)}
                self._run_listener(new_sid, 'connect')
                return json.dumps({'action': 'connect', 'sid': new_sid})
            if request.args['sid'] not in self._clients:
                return json.dumps({'action': 'disconnect'})
            if request.method == 'POST':
                if request.form.get('action', '') == 'event':
                    self._run_listener(request.args['sid'], request.form['name'], request.form['data'])
                    return 'ok'
                if request.form.get('action', '') == 'disconnect':
                    del self._clients[request.args['sid']]
                    return 'ok'
            if self._clients[request.args['sid']]['queue'].empty():
                return json.dumps({'action': 'retry'})
            return self._clients[request.args['sid']]['queue'].get()

    def on(self, event_name, func):
        item = self._listeners.get(event_name, [])
        item.append(func)
        self._listeners[event_name] = item

    def emit(self, sid, event_name, data):
        if sid not in self._clients:
            return
        self._clients[sid]['queue'].put(json.dumps({'action': 'event', 'name': event_name, 'data': data}))

    def _run_listener(self, sid, event_name, data=None):
        for listener in self._listeners.get(event_name, []):
            AsyncExecuter(self._clients[sid]['socket'], listener, data).start()


class HSocket:
    def __init__(self, socket_server: HTTPSocketServer, sid: str):
        self.server = socket_server
        self.sid = sid

    def emit(self, function_name, data):
        self.server.emit(self.sid, function_name, data)


class AsyncExecuter(Thread):
    def __init__(self, client, func, data=None):
        Thread.__init__(self)
        self.client = client
        self.func = func
        self.data = data

    def run(self):
        self.func(self.client, self.data) if self.data is not None else self.func(self.client)
