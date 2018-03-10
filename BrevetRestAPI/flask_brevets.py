"""
Replacement for RUSA ACP brevet time calculator
(see https://rusa.org/octime_acp.html)

"""

import flask
from flask import request, abort, session
from pymongo import *
import arrow  # Replacement for datetime, based on moment.js
import acp_times  # Brevet time calculations
import config
import datetime

from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer \
                                  as Serializer, BadSignature, \
                                  SignatureExpired)

import logging

###
# Globals
###
app = flask.Flask(__name__)
CONFIG = config.configuration()
app.secret_key = CONFIG.SECRET_KEY

client = MongoClient(CONFIG.MONGO_URI)
db = client.get_default_database()
brevet_times_col = db['brevet_times']
user_col = db["users"]

###
# Pages
###


@app.route("/")
@app.route("/index")
def index():
    app.logger.debug("Main page entry")
    return flask.render_template('calc.html')


@app.errorhandler(404)
def page_not_found(error):
    app.logger.debug("Page not found")
    flask.session['linkback'] = flask.url_for("index")
    return flask.render_template('404.html'), 404


###############
#
# AJAX request handlers
#   These return JSON, rather than rendering pages.
#
###############
@app.route("/_calc_times")
def _calc_times():
    """
    Calculates open/close times from miles, using rules
    described at https://rusa.org/octime_alg.html.
    Expects one URL-encoded argument, the number of miles.
    """
    app.logger.debug("Got a JSON request")
    km = request.args.get('km', 999, type=float)
    brevet = request.args.get('brevet', type=int)
    start_info = request.args.get('start_info', type=str)
    app.logger.debug("km={}".format(km))
    app.logger.debug("request.args: {}".format(request.args))
    open_time = acp_times.open_time(km, brevet, start_info)
    close_time = acp_times.close_time(km, brevet, start_info)
    result = {"open": open_time, "close": close_time}
    return flask.jsonify(result=result)

@app.route("/_submit_times_db")
def _submit_times_db():
    token = session['token']
    if verify_auth_token(token) == None:
        abort(401)

    username = request.args.get("username", type=str)

    brevet_times_col.delete_many({"un": username})

    miles = request.args.get("miles", type=str).split("|")
    km = request.args.get("km", type=str).split("|")
    openTime = request.args.get("open", type=str).split("|")
    closeTime = request.args.get("close", type=str).split("|")

    num_controls = len(miles)

    print(miles)
    print(km)
    print(openTime)
    print(closeTime)

    for control in range(num_controls - 1):
        brevet_times_col.insert({
                                "un": username,
                                "miles": miles[control],
                                "km": km[control],
                                "openTime": openTime[control],
                                "closeTime": closeTime[control]
                                })
    return ""

@app.route("/listAll")
@app.route("/listAll/json")
def json_listAll():
    username = request.args.get("username", default = "", type=str)
    k = request.args.get("top", default = -1, type=int)
    token = session['token']
    if verify_auth_token(token) == None:
        abort(401)
    controls = brevet_times_col.find({})
    containerString = "<html>"
    containerString += '{<br/>&emsp;"results" : [<br/>'
    openTimes = []
    closeTimes = []
    for entries in controls:
        if entries["un"] == username:
            openTimes.append(entries['openTime'])
            closeTimes.append(entries['closeTime'])
    if k != -1:
        # Sorting Code from : https://stackoverflow.com/a/17627575
        openTimes.sort(key=lambda x: datetime.datetime.strptime(x, ' %m/%d %H:%M'))
        closeTimes.sort(key=lambda x: datetime.datetime.strptime(x, ' %m/%d %H:%M'))
    for i in range(len(openTimes)):
        if i == k: #Break when i = k to only display top k results.  If for loop went from 0 to k, if k > len(openTimes) it would error, this prevents that
            break
        containerString += "&emsp;&emsp;{"
        containerString += '<br/>&emsp;&emsp;&emsp;"openTime" : ' + openTimes[i] + ",<br/>&emsp;&emsp;&emsp;" + '"closeTime" : ' + closeTimes[i] + "<br/>"
        containerString += "&emsp;&emsp;},<br/>"
    containerString = containerString[:-6]
    containerString += "<br/>&emsp;]<br/>}"
    containerString += "</html>"
    return flask.jsonify(result=containerString)

@app.route("/listOpenOnly")
@app.route("/listOpenOnly/json")
def json_listOpenOnly():
    username = request.args.get("username", default = "", type=str)
    k = request.args.get("top", default = -1, type=int)
    token = session['token']
    if verify_auth_token(token) == None:
        abort(401)
    controls = brevet_times_col.find({})
    containerString = "<html>"
    containerString += '{<br/>&emsp;"results" : [<br/>'
    openTimes = []
    for entries in controls:
        if entries["un"] == username:
            openTimes.append(entries['openTime'])
    if k != -1:
        # Sorting Code from : https://stackoverflow.com/a/17627575
        openTimes.sort(key=lambda x: datetime.datetime.strptime(x, ' %m/%d %H:%M'))
    for i in range(len(openTimes)):
        if i == k: #Break when i = k to only display top k results.  If for loop went from 0 to k, if k > len(openTimes) it would error, this prevents that
            break
        containerString += "&emsp;&emsp;{"
        containerString += '<br/>&emsp;&emsp;&emsp;"openTime" : ' + openTimes[i] + "<br/>"
        containerString += "&emsp;&emsp;},<br/>"
    containerString = containerString[:-6]
    containerString += "<br/>&emsp;]<br/>}"
    containerString += "</html>"
    return flask.jsonify(result=containerString)

@app.route("/listCloseOnly")
@app.route("/listCloseOnly/json")
def json_listCloseOnly():
    username = request.args.get("username", default = "", type=str)
    k = request.args.get("top", default = -1, type=int)
    token = session['token']
    if verify_auth_token(token) == None:
        abort(401)
    controls = brevet_times_col.find({})
    containerString = "<html>"
    containerString += '{<br/>&emsp;"results" : [<br/>'
    openTimes = []
    closeTimes = []
    for entries in controls:
        if entries["un"] == username:
            closeTimes.append(entries['closeTime'])
    if k != -1:
        # Sorting Code from : https://stackoverflow.com/a/17627575
        closeTimes.sort(key=lambda x: datetime.datetime.strptime(x, ' %m/%d %H:%M'))
    for i in range(len(closeTimes)):
        if i == k: #Break when i = k to only display top k results.  If for loop went from 0 to k, if k > len(openTimes) it would error, this prevents that
            break
        containerString += "&emsp;&emsp;{"
        containerString += '<br/>&emsp;&emsp;&emsp;"closeTime" : ' + closeTimes[i] + "<br/>"
        containerString += "&emsp;&emsp;},<br/>"
    containerString = containerString[:-6]
    containerString += "<br/>&emsp;]<br/>}"
    containerString += "</html>"
    return flask.jsonify(result=containerString)

@app.route("/listAll/csv")
def csv_listAll():
    username = request.args.get("username", default = "", type=str)
    k = request.args.get("top", default = -1, type=int)
    token = session['token']
    if verify_auth_token(token) == None:
        abort(401)
    controls = brevet_times_col.find({})
    containerString = "<html>Open, Close<br/>"
    openTimes = []
    closeTimes = []
    for entries in controls:
        if entries["un"] == username:
            openTimes.append(entries['openTime'])
            closeTimes.append(entries['closeTime'])
    if k != -1:
        # Sorting Code from : https://stackoverflow.com/a/17627575
        openTimes.sort(key=lambda x: datetime.datetime.strptime(x, ' %m/%d %H:%M'))
        closeTimes.sort(key=lambda x: datetime.datetime.strptime(x, ' %m/%d %H:%M'))
    for i in range(len(openTimes)):
        if i == k: #Break when i = k to only display top k results.  If for loop went from 0 to k, if k > len(openTimes) it would error, this prevents that
            break
        containerString += openTimes[i] + ", " + closeTimes[i] + "<br/>"
    containerString += "</html>"
    return flask.jsonify(result=containerString)

@app.route("/listOpenOnly/csv")
def csv_listOpenOnly():
    username = request.args.get("username", default = "", type=str)
    k = request.args.get("top", default = -1, type=int)
    token = session['token']
    if verify_auth_token(token) == None:
        abort(401)
    controls = brevet_times_col.find({})
    containerString = "<html>Open<br/>"
    openTimes = []
    for entries in controls:
        if entries["un"] == username:
            openTimes.append(entries['openTime'])
    if k != -1:
        # Sorting Code from : https://stackoverflow.com/a/17627575
        openTimes.sort(key=lambda x: datetime.datetime.strptime(x, ' %m/%d %H:%M'))
    for i in range(len(openTimes)):
        if i == k: #Break when i = k to only display top k results.  If for loop went from 0 to k, if k > len(openTimes) it would error, this prevents that
            break
        containerString += openTimes[i] + "<br/>"
    containerString += "</html>"
    return flask.jsonify(result=containerString)

@app.route("/listCloseOnly/csv")
def csv_listCloseOnly():
    username = request.args.get("username", default = "", type=str)
    k = request.args.get("top", default = -1, type=int)
    token = session['token']
    if verify_auth_token(token) == None:
        abort(401)
    controls = brevet_times_col.find({})
    containerString = "<html>Close<br/>"
    closeTimes = []
    for entries in controls:
        if entries["un"] == username:
            closeTimes.append(entries['closeTime'])
    if k != -1:
        # Sorting Code from : https://stackoverflow.com/a/17627575
        closeTimes.sort(key=lambda x: datetime.datetime.strptime(x, ' %m/%d %H:%M'))
    for i in range(len(closeTimes)):
        if i == k: #Break when i = k to only display top k results.  If for loop went from 0 to k, if k > len(openTimes) it would error, this prevents that
            break
        containerString += closeTimes[i] + "<br/>"
    containerString += "</html>"
    return flask.jsonify(result=containerString)

# Used in registering user
def hash_password(password):
    return pwd_context.hash(password)

@app.route("/api/register")
def _register_user():
    username = request.args.get("username", default = "", type=str)
    plain_password = request.args.get("password", default = "", type=str)
    users = user_col.find({})
    for entries in users:
        if entries["un"] == username:
            abort(400)
    hashed_password = hash_password(plain_password)
    plain_password = None
    user_col.insert({
                    "un": username,
                    "password": hashed_password
                    })
    location = None
    for entries in users:
        if entries["un"] == username:
            location = entries["_id"]
            break
    result = {"Location": location, "username": username, "password": hashed_password}
    return flask.jsonify(result=result), 201

# Used in basic HTTP authentication
def verify_password(password, hashVal):
    return pwd_context.verify(password, hashVal)

def generate_auth_token(_id, expiration=600):
    s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
    return s.dumps({"id": _id})

@app.route("/api/token")
def _return_token():
    username = request.args.get("username", default = "", type=str)
    password = request.args.get("password", default = "", type=str)
    match = False
    uuid = None
    hashed_password = None

    users = user_col.find({})
    for entries in users:
        if entries["un"] == username:
            uuid = str(entries["_id"])
            hashed_password = entries["password"]
            match = True
            break

    if match == False:
        abort(401)

    if verify_password(password, hashed_password):
        token = generate_auth_token(uuid, 600)
        session['token'] = token
        result = {'token': str(token), 'duration': 600}
        return flask.jsonify(result=result)
    else:
        abort(401)

# Used in every important redirect to make sure it is protected
def verify_auth_token(token):
    s = Serializer(app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except SignatureExpired:
        return None    # valid token, but expired
    except BadSignature:
        return None    # invalid token
    return "Success"

#############

app.debug = CONFIG.DEBUG
if app.debug:
    app.logger.setLevel(logging.DEBUG)

if __name__ == "__main__":
    print("Opening for global access on port {}".format(CONFIG.PORT))
    app.run(port=CONFIG.PORT, host="0.0.0.0")
