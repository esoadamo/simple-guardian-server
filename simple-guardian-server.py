from flask import Flask, render_template, session, request, redirect, url_for
import socketio
import eventlet.wsgi
from http_socket_server import HTTPSocketServer

sio = socketio.Server()
app = Flask(__name__)


@app.route("/api/serviceName")
def get_new_sid():
    return "simple-guardian-server"


if __name__ == '__main__':
    hsoc = HTTPSocketServer(app)

    def connect(soc):
        print(soc.sid, 'just connected')
        import time
        time.sleep(2)
        soc.emit('hello', 'how are you?')

    def greetings(soc, data):
        print(soc.sid, ':', data)

    hsoc.on('connect', connect)
    hsoc.on('helloBack', greetings)
    app = socketio.Middleware(sio, app)
    eventlet.wsgi.server(eventlet.listen(('', 5000)), app)
