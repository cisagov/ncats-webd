import json
import random
import copy
from datetime import datetime, timedelta
import time
import urllib

# from bson import json_util

from flask import Blueprint, render_template, redirect, current_app, url_for, request

from cyhy.util import util
from ncats_webd.common import cache

BLUEPRINT_NAME = "status"
bp = Blueprint(
    BLUEPRINT_NAME, __name__, template_folder="templates", static_folder="static"
)

###############################################################################
#  Data Access
###############################################################################


@cache.memoize(timeout=30)
def json_all_status(since=None):
    docs = list(current_app.db.TallyDoc.get_all(since))
    return json.dumps(docs, default=util.custom_json_handler)


@cache.memoize(timeout=30)
def json_status(owner):
    result = {}
    result["tally"] = current_app.db.TallyDoc.get_by_owner(owner)
    result["request"] = current_app.db.RequestDoc.get_by_owner(owner)
    return json.dumps(result, default=util.custom_json_handler)


###############################################################################
#  Routes
###############################################################################


@bp.route("/")
def root():
    # data request
    if request.args.has_key("j"):
        max_age = int(request.args.get("maxage", 0))
        if max_age == 0:
            since = None
        else:
            since = datetime.utcfromtimestamp(time.time() - max_age)
        return json_all_status(since)

    # template request
    return render_template("status.html")


@bp.route("/<encoded_acronym>")
def scan_json(encoded_acronym):
    decoded_acronym = urllib.unquote(encoded_acronym)
    # data request
    if request.args.has_key("j"):
        return json_status(decoded_acronym)

    # template request
    return render_template(
        "details.html", acronym=decoded_acronym, encoded_acronym=encoded_acronym
    )
