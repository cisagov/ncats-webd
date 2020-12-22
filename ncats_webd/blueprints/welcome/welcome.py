from flask import Blueprint, render_template, current_app
from flask_socketio import join_room, leave_room

from ncats_webd.common import cache, socketio

BLUEPRINT_NAME = "welcome"
bp = Blueprint(
    BLUEPRINT_NAME, __name__, template_folder="templates", static_folder="static"
)


@bp.route("/")
def root():
    return render_template("welcome.html")


@bp.route("/rr")
def coming_soons():
    return render_template("soon.html")


@bp.route("/prefs")
def preferences():
    return render_template("prefs.html")


@socketio.on("connect", namespace="/cyhy")
def sys_connect():
    current_app.logger.info("client connected")


@socketio.on("disconnect", namespace="/cyhy")
def sys_disconnect():
    current_app.logger.info("client disconnected")


@socketio.on("join", namespace="/cyhy")
def join(message):
    join_room(message["room"])
    current_app.logger.info("client joined room %s" % message["room"])


@socketio.on("unjoin", namespace="/cyhy")
def join(message):
    leave_room(message["room"])
    current_app.logger.info("client left room %s" % message["room"])
