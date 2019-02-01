from uuid import uuid4
from flask import request
import json
from queue import Queue
from threading import Thread
import time


class HTTPSocketServer:
    def __init__(self, flask_app):
        """
        Starts the HTTPSocketServer
        :param flask_app: Flasks app
        """
        self._listeners = {}  # event name: function to call upon firing of the event
        self._clients = {}  # sid: {queue: Queue, socket: HSocket, accessTime: last time accessed)
        self._closed = False  # server is shutting down and does not accept any connections anymore

        class ThreadIncactiveClientsRemover(Thread):
            """
            Disconnects clients that were inactive more than 15 seconds
            """
            # noinspection PyMethodParameters
            def run(__):
                while not self._closed:
                    timed_out_clients = []
                    for client, client_data in self._clients.items():
                        if time.time() - client_data['accessTime'] > 15:
                            timed_out_clients.append(client)
                    for client in timed_out_clients:
                        self._disconnect(client)
                    time.sleep(15)

        ThreadIncactiveClientsRemover().start()

        @flask_app.route("/hsocket/", methods=['GET', 'POST'])
        def handler():
            """
            Handles requests to the /hsocket/ path of the Flask server
            GET is used when asking for data
            POST is used when client wants something to do
            """
            if 'sid' not in request.args:
                # client is connected for the first time, generate a fancy uuid for him
                while True:
                    new_sid = uuid4().hex
                    if new_sid not in self._clients:
                        break
                self._clients[new_sid] = {'queue': Queue(), 'socket': HSocket(self, new_sid), 'accessTime': time.time()}
                self._run_listener(new_sid, 'connect')
                return json.dumps({'action': 'connect', 'sid': new_sid})

            if request.args['sid'] not in self._clients:
                # this man has some weird sid, disconnect him and let him obtain a new one
                return json.dumps({'action': 'disconnect'})

            # update the last time client connected to the server
            self._clients[request.args['sid']]['accessTime'] = time.time()

            if request.method == 'POST':
                if request.form.get('action', '') == 'event':  # fire an event
                    self._run_listener(request.args['sid'], request.form['name'], request.form['data'])
                    return 'ok'
                if request.form.get('action', '') == 'disconnect':  # disconnect client
                    self._disconnect(request.args['sid'])
                    return 'ok'
                return 'invalid post'

            # client wants to ask if we have some data for him
            if self._clients[request.args['sid']]['queue'].empty():
                return json.dumps({'action': 'retry'})  # no, we do not
            return self._clients[request.args['sid']]['queue'].get()  # yes, we do!

    def on(self, event_name, func):  # type: (str, "function") -> None
        """
        Sets a new listener for an event
        :param event_name: name of the event that the listener shall listen for
        :param func: function fired upon calling of this event. Calls are performed like func(event_data)
        :return: None
        """
        item = self._listeners.get(event_name, [])
        item.append(func)
        self._listeners[event_name] = item

    def emit(self, sid, event_name, data=None):  # type: (str, str, any) -> None
        """
        Fire an event with specified data
        :param sid: socket ID of the target client
        :param event_name: Name of the event to fire on the client
        :param data: data passed to the fired function
        :return: None
        """
        if sid not in self._clients:
            return
        self._clients[sid]['queue'].put(json.dumps({'action': 'event', 'name': event_name, 'data': data}))

    def set_asking_timeout(self, sid, timeout: float):
        """
        Set the maximum interval in which will the client ask us for new data
        :param sid: socket ID of the target client
        :param timeout: maximum asking interval in seconds
        :return: None
        """
        if sid not in self._clients:
            return
        self._clients[sid]['queue'].put(json.dumps({'action': 'set_max_msg_interval', 'data': timeout}))

    def close(self):
        """
        Mark this server as closed and disconnect all clients
        :return: None
        """
        self._closed = True

    def _run_listener(self, sid, event_name, data=None):  # type: (str, str, any) -> None
        """
        Runs asynchronously all listeners for specified event
        :param sid: socket ID of the client that fired this event on the server
        :param event_name: name of the event listeners to run
        :param data: data to pass to the listening functions
        :return: None
        """
        for listener in self._listeners.get(event_name, []):
            AsyncExecuter(self._clients[sid]['socket'], listener, data).start()

    def _disconnect(self, sid):
        """
        Executes when client disconnects. Fires 'disconnect' listener and removes him from active client
        :param sid: socket ID of the client that has disconnected
        :return: None
        """
        self._run_listener(sid, 'disconnect')
        del self._clients[sid]


class HSocket:
    """
    Represents client connected to this HSocket server
    """

    def __init__(self, socket_server: HTTPSocketServer, sid: str):
        """
        Initialize this client
        :param socket_server: instance of HTTPSocketServer that servers this client
        :param sid: socket ID of client
        """
        self.server = socket_server
        self.sid = sid

    def emit(self, event_name, data=None):  # type: (str, any) -> None
        """
        Fire an event with specified data
        :param event_name: Name of the event to fire on the client device
        :param data: data passed to the fired function
        :return: None
        """
        self.server.emit(self.sid, event_name, data)

    def set_asking_timeout(self, timeout: float):
        """
        Set the maximum interval in which will the client ask us for new data
        :param timeout: maximum asking interval in seconds
        :return: None
        """
        self.server.set_asking_timeout(self.sid, timeout)


class AsyncExecuter(Thread):
    """
    Executes a function asynchronously
    """

    def __init__(self, client, func, data=None):  # type: (HSocket, "function", any) -> None
        """
        Initializes the data for asynchronous execution.
        The execution itself must be then started by using .start()
        :param client: the HSocket instance of client that is firing this function on us
        :param func: function to execute
        :param data: data passed to the executed function
        """
        Thread.__init__(self)
        self.client = client
        self.func = func
        self.data = data

    def run(self):
        self.func(self.client, self.data) if self.data is not None else self.func(self.client)
