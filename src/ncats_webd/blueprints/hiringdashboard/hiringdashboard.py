import json
import re
import datetime
from collections import deque

from flask import Blueprint, render_template, abort, current_app, request, logging
from flask_socketio import send, emit
from bson.objectid import ObjectId
from bson.json_util import dumps
import schedule
import time
import json
import math

from cyhy.util import util
from cyhy.db import database
from ncats_webd.common import cache, socketio, catch_exceptions
from ncats_webd.queries import HiringDashboardQueries

# import IPython; IPython.embed() #<<< BREAKPOINT >>>

BLUEPRINT_NAME = "hiringdashboard"
bp = Blueprint(
    BLUEPRINT_NAME, __name__, template_folder="templates", static_folder="static"
)

REFRESH_INTERVAL = 30 * 60
OID_RE = re.compile(r"^[0-9a-f]{24}$")
TID_RE = re.compile(r"^[/A-Za-z0-9]+$")
SOURCE_ID_RE = re.compile(r"^nessus:[0-9]+$")
new_hire_feed = None


class NewHireFeed(object):
    # TODO decrease sleep_time after testing query load on db
    def __init__(self, db, emitter, logger, sleep_time=3000, history_size=100):
        self.__db = db
        self.__emitter = emitter
        self.__logger = logger
        self.__sleep_time = sleep_time
        self.__since = util.utcnow() - datetime.timedelta(minutes=30)
        self.__history = deque(maxlen=history_size)
        schedule.every(sleep_time).seconds.do(self.__work)

    @catch_exceptions
    def __work(self):
        self.__logger.debug("checking for updated tickets")
        new_tickets = self.__check_database()
        if new_tickets:
            self.__logger.debug("found %d updated tickets" % len(new_tickets))
            self.__history.extend(new_tickets)
            self.__emitter(new_tickets)
        else:
            self.__logger.debug("no updated tickets found")

    def __check_database(self):
        now = util.utcnow()
        tickets = self.__db.new_hire.find({"latest": True})
        tickets = list(tickets)
        for (
            x
        ) in tickets:  # convert _ids to string since we can't set custom json handler
            x["_id"] = str(x["_id"])
        self.__since = now
        return tickets

    @property
    def history(self):
        return list(self.__history)


###############################################################################
#  Server side event generation
###############################################################################


@bp.before_app_first_request
def start_background_thread():
    global new_hire_feed
    if new_hire_feed is None:
        new_hire_feed = NewHireFeed(
            current_app.new_hire_db, broadcast_new_hire_metrics(), current_app.logger
        )
    # TODO: Probably throwing exception quietly
    @catch_exceptions
    def job():
        broadcast_new_hire_metrics()

    schedule.every(600).seconds.do(job)


###############################################################################
#  Data Access
###############################################################################


def latest_billet_status():
    return [{"latest": True}], database.NEW_HIRE_COLLECTION


@cache.memoize(timeout=REFRESH_INTERVAL)
def json_get_hire_metrics():
    metrics = HiringDashboardQueries.get_current_billets(current_app.new_hire_db)
    try:
        for doc in metrics:
            weeks_in_stage = [None] * 10
            # For each stage between 1 and current stage -1
            for stage in range(0, int(doc["current_stage"]) - 1):
                # Find difference in stage +1 and stage
                weeks_in_stage[stage] = round(
                    (
                        doc["date_stage_entered"][stage + 1]
                        - doc["date_stage_entered"][stage]
                    ).days
                    / 7.0
                )
            # Difference in current stage and insert date
            weeks_in_stage[stage + 1] = round(
                (doc["insert_date"] - doc["date_stage_entered"][stage + 1]).days / 7.0
            )
            # Append the number of weeks in stage to each Doc
            doc["weeks_in_stage"] = weeks_in_stage
    except Exception as e:
        print(
            "Trying to do arithmetic on null. This shouldn't happen unless someone manually changed the database."
            " \n Error: {}".format(e)
        )
    return json.dumps(metrics, default=util.custom_json_handler)


###############################################################################
#  Socket.io Handlers
###############################################################################


@socketio.on("new_hire_metrics_latest", namespace="/cyhy")
def new_hire_metrics_latest_event():
    current_app.logger.info("client requested new hire metric data")
    emit("new_hire_metrics", {"data": json_get_hire_metrics()})


###############################################################################
#  Socket.io Senders
###############################################################################


def broadcast_new_hire_metrics():
    new_hire_metrics = json_get_hire_metrics()
    socketio.emit(
        "new_hire_metrics",
        {"data": new_hire_metrics},
        namespace="/cyhy",
        room="new_hire_metrics",
    )
