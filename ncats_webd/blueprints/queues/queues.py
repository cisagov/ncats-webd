import json
import re
from collections import defaultdict, OrderedDict

from flask import Blueprint, render_template, abort, current_app, request
from flask_socketio import send, emit
from bson.objectid import ObjectId
from dateutil import parser, tz

import datetime
from pandas import Series, DataFrame
import pandas as pd
import numpy as np
import schedule

from cyhy.util import util
from cyhy.db import database
from cyhy.core import STAGE, STATUS
from ncats_webd.common import cache, socketio, catch_exceptions
from ncats_webd.queries import DashboardQueries

BLUEPRINT_NAME = "queues"
bp = Blueprint(
    BLUEPRINT_NAME, __name__, template_folder="templates", static_folder="static"
)

REFRESH_INTERVAL = 300

###############################################################################
#  Server side event generation
###############################################################################


@bp.before_app_first_request
def schedule_broadcaster():
    current_app.logger.info("setting up %s broadcast schedule" % BLUEPRINT_NAME)

    @catch_exceptions
    def job():
        broadcast_queue_update()

    schedule.every(REFRESH_INTERVAL + 1).seconds.do(job)


###############################################################################
#  Utils
###############################################################################

###############################################################################
#  Pipelines
###############################################################################

###############################################################################
#  Data Access
###############################################################################


@cache.memoize(timeout=REFRESH_INTERVAL)
def json_get_running_times():
    now = util.utcnow()  # .replace(tzinfo=None) # everything is implicitly UTC

    running_times = current_app.db.HostDoc.find(
        {"status": "RUNNING"}, {"_id": False, "last_change": True, "stage": True}
    )

    running_times = list(running_times)

    df = DataFrame(running_times)
    df["age"] = ((now - df["last_change"]) / np.timedelta64(1, "s")).astype(
        int
    )  # timedelta to seconds
    df["tally"] = 1
    df = df.set_index(["stage", "age"])
    g = df.groupby(level=["stage", "age"])
    df2 = g.sum()
    df2 = df2.fillna(0)

    results = OrderedDict()  # the order matters to c3js
    results["x"] = list(df2.loc["NETSCAN1"].index)
    # TODO stages not guaranteed to be in index
    results["NETSCAN1"] = list(df2.loc["NETSCAN1"]["tally"].astype(int))
    results["NETSCAN2"] = list(df2.loc["NETSCAN2"]["tally"].astype(int))
    results["PORTSCAN"] = list(df2.loc["PORTSCAN"]["tally"].astype(int))
    results["VULNSCAN"] = list(df2.loc["VULNSCAN"]["tally"].astype(int))
    # import IPython; IPython.embed() #<<< BREAKPOINT >>>

    return json.dumps(results, default=util.custom_json_handler)


@cache.memoize(timeout=REFRESH_INTERVAL)
def json_get_tally_details():
    results = DashboardQueries.get_tally_details(current_app.db)
    # import IPython; IPython.embed() #<<< BREAKPOINT >>>
    return json.dumps(results, default=util.custom_json_handler)


###############################################################################
#  Routes
###############################################################################


@bp.route("/time")
def running_times():
    # data request
    if request.args.has_key("j"):
        return json_get_running_times()

    # template request
    return render_template("times.html", refresh_interval=REFRESH_INTERVAL / 2)


@bp.route("/")
def tally_priorities():
    if request.args.has_key("j"):
        return json_get_tally_details()

    # template request
    return render_template("queues_sa.html", refresh_interval=REFRESH_INTERVAL / 2)


###############################################################################
#  Socket.io Handlers
###############################################################################


@socketio.on("queues_latest", namespace="/cyhy")
def latest_queues():
    current_app.logger.info("client requested latest queues data")
    emit("queues_data_push", {"data": json_get_tally_details()})


###############################################################################
#  Socket.io Senders
###############################################################################


def broadcast_queue_update():
    current_app.logger.debug("broadcasting queue data")
    data = json_get_tally_details()
    data = {"data": data}
    # Note: emit will json encode our object with json data.
    # so we need to call JSON.parse on the json string
    # to reconstitue the object client-side.
    socketio.emit("queues_data_push", data, namespace="/cyhy", room="queues")
