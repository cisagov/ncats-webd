#!/usr/bin/env python

"""Pulls the data needed for the CyHy Dashboard and pushes it to a server in our DMZ.

Usage:
  COMMAND_NAME [--section SECTION]
  COMMAND_NAME (-h | --help)
  COMMAND_NAME --version

Options:
  -h --help                      Show this screen.
  --version                      Show version.
  -s SECTION --section=SECTION   Configuration section to use.

"""

import sys
import os
import re
from docopt import docopt
from cyhy.core import STAGE, STATUS
from cyhy.db import database
from cyhy.util import util, setup_logging
import json
import schedule
import time
from fabric.tasks import Task, execute
from fabric.api import task, env
from fabric import operations
import logging

REFRESH_INTERVAL = 300
env.use_ssh_config = True  # env used by fabric
DESTINATION_HOSTS = ["drop.ncats.dhs.gov"]
DESTINATION_DIR = "dashdog/data_drop/"
TICKET_COUNT_FILENAME = "ticket_counts.json"
OVERALL_METRICS_FILENAME = "overall.json"
TALLY_COUNT_FILENAME = "queue_counts.json"
OPEN_TICKET_LOCATIONS_FILENAME = "active_vulns_loc.json"
OPEN_TICKET_LOCATIONS_1_FILENAME = "active_vulns_loc_1.json"
OPEN_TICKET_LOCATIONS_2_FILENAME = "active_vulns_loc_2.json"
OPEN_TICKET_LOCATIONS_3_FILENAME = "active_vulns_loc_3.json"
OPEN_TICKET_LOCATIONS_4_FILENAME = "active_vulns_loc_4.json"
RUNNING_IPS_FILENAME = "running_scans.json"
HOST_LOCATIONS_FILENAME = "host_locations.json"

DEFAULT_LOGGER_LEVEL = logging.INFO
LOG_FILE = "data-pusher.log"
root = setup_logging(DEFAULT_LOGGER_LEVEL, filename=LOG_FILE)
logger = logging.getLogger(__name__)


@task
def push_data(source_file_list, destination_dir):
    for filename in source_file_list:
        paths = operations.put(filename, destination_dir)
        if len(paths.failed) == 0:
            logger.info(
                "{!s} was pushed successfully to {!s}".format(filename, env.host_string)
            )
        else:
            logger.error(
                "Error pushing {!s} to host {!s}".format(filename, env.host_string)
            )


def build_stakeholder_list(db):
    stakeholders = []
    for r in db.requests.find({"stakeholder": True}):
        stakeholders.append(r["_id"])
    return stakeholders


def get_ticket_severity_counts(db, stakeholders):
    results = dict()
    results["ticket_data"] = dict()
    for org in db.requests.find({"stakeholder": True}):
        if org.get("children"):
            current_org_list = [org["_id"]] + db.RequestDoc.get_all_descendants(
                org["_id"]
            )
        else:
            current_org_list = [org["_id"]]
        tix = db.tickets.aggregate(
            [
                {
                    "$match": {
                        "open": True,
                        "source": "nessus",
                        "owner": {"$in": current_org_list},
                        "false_positive": False,
                    }
                },
                {
                    "$group": {
                        "_id": {},
                        "critical_tix_open": {
                            "$sum": {"$cond": [{"$eq": ["$details.severity", 4]}, 1, 0]}
                        },
                        "high_tix_open": {
                            "$sum": {"$cond": [{"$eq": ["$details.severity", 3]}, 1, 0]}
                        },
                    }
                },
            ]
        )

        if tix["result"]:
            results["ticket_data"][org["_id"]] = {
                "org_name": org["agency"]["name"],
                "critical_open": tix["result"][0].get("critical_tix_open"),
                "high_open": tix["result"][0].get("high_tix_open"),
            }
        else:
            results["ticket_data"][org["_id"]] = {
                "org_name": org["agency"]["name"],
                "critical_open": 0,
                "high_open": 0,
            }

    # Reverse sort on critical_open, then high_open, then normal (alphabetical) sort on org_name
    sorted_ticket_data = sorted(
        results["ticket_data"].values(),
        key=lambda (v): (-v["critical_open"], -v["high_open"], v["org_name"]),
    )
    return sorted_ticket_data


def get_overall_metrics(db, stakeholders):
    results = dict()
    results["stakeholders"] = len(stakeholders)
    results["addresses"] = db.hosts.count()
    results["hosts"] = db.hosts.find({"state.up": True}).count()
    results["vulnerable_hosts"] = len(
        db.tickets.find(
            {"open": True, "source": "nessus", "false_positive": False}
        ).distinct("ip_int")
    )

    tix = db.tickets.aggregate(
        [
            {"$match": {"open": True, "source": "nessus", "false_positive": False}},
            {
                "$group": {
                    "_id": {},
                    "low_tix_open": {
                        "$sum": {"$cond": [{"$eq": ["$details.severity", 1]}, 1, 0]}
                    },
                    "medium_tix_open": {
                        "$sum": {"$cond": [{"$eq": ["$details.severity", 2]}, 1, 0]}
                    },
                    "high_tix_open": {
                        "$sum": {"$cond": [{"$eq": ["$details.severity", 3]}, 1, 0]}
                    },
                    "critical_tix_open": {
                        "$sum": {"$cond": [{"$eq": ["$details.severity", 4]}, 1, 0]}
                    },
                    "total_tix_open": {"$sum": 1},
                }
            },
        ]
    )

    results["open_tickets"] = {
        "low": tix["result"][0]["low_tix_open"],
        "medium": tix["result"][0]["medium_tix_open"],
        "high": tix["result"][0]["high_tix_open"],
        "critical": tix["result"][0]["critical_tix_open"],
        "total": tix["result"][0]["total_tix_open"],
    }

    results["reports"] = db.reports.count()
    return results


def tuple_list(df, stage, status):
    rec_array = df[stage][status].reset_index(drop=True).T.to_records()
    return [tuple(i) for i in rec_array]


def priority_counts_pl():
    return (
        [
            {"$match": {"status": {"$ne": "DONE"}}},
            {
                "$group": {
                    "_id": {
                        "status": "$status",
                        "stage": "$stage",
                        "priority": "$priority",
                    },
                    "total": {"$sum": 1},
                }
            },
            {"$sort": {"_id.priority": 1}},
        ],
        database.HOST_COLLECTION,
    )


def get_tally_details(db):
    results = dict()
    stage_status_counts = db.hosts.aggregate(
        [
            {
                "$group": {
                    "_id": {"stage": "$stage", "status": "$status"},
                    "count": {"$sum": 1},
                }
            }
        ]
    )
    for (queue_name, stage, status) in [
        ("ns1_waiting", STAGE.NETSCAN1, [STATUS.WAITING, STATUS.READY]),
        ("ns1_running", STAGE.NETSCAN1, [STATUS.RUNNING]),
        ("ns2_waiting", STAGE.NETSCAN2, [STATUS.WAITING, STATUS.READY]),
        ("ns2_running", STAGE.NETSCAN2, [STATUS.RUNNING]),
        ("ps_waiting", STAGE.PORTSCAN, [STATUS.WAITING, STATUS.READY]),
        ("ps_running", STAGE.PORTSCAN, [STATUS.RUNNING]),
        ("vs_waiting", STAGE.VULNSCAN, [STATUS.WAITING, STATUS.READY]),
        ("vs_running", STAGE.VULNSCAN, [STATUS.RUNNING]),
    ]:
        for i in stage_status_counts["result"]:
            if i["_id"]["stage"] == stage and i["_id"]["status"] in status:
                if results.get(queue_name):
                    results[queue_name] += i["count"]
                else:
                    results[queue_name] = i["count"]
    return results


def get_open_ticket_loc_by_severity(db, severity=None):
    if severity != None:
        tickets = db.TicketDoc.collection.find(
            {
                "open": True,
                "source": "nessus",
                "details.severity": severity,
                "loc.0": {"$ne": None},
            },
            {"_id": 0, "loc": 1, "details.severity": 1},
        )
    else:
        tickets = db.TicketDoc.collection.find(
            {"open": True, "source": "nessus", "loc.0": {"$ne": None}},
            {"_id": 0, "loc": 1, "details.severity": 1},
        )
    return list(tickets)


def get_running_ips(db):
    running_ips = db.HostDoc.collection.find(
        {"status": "RUNNING"}, {"_id": 0, "loc": 1, "stage": 1}
    )
    return list(running_ips)


def get_host_locations(db):
    host_locations = db.HostDoc.collection.find(
        {"state.up": True}, {"_id": 0, "loc": 1}
    )
    return list(host_locations)


def generate_push_data_files(db):
    logger.info("generating dashboard data; starting db queries")
    stakeholders = build_stakeholder_list(db)
    ticket_severity_counts = get_ticket_severity_counts(db, stakeholders)
    overall_metrics = get_overall_metrics(db, stakeholders)
    tally_details = get_tally_details(db)
    open_ticket_locations = dict()
    open_ticket_locations[0] = get_open_ticket_loc_by_severity(db)
    for severity in (1, 2, 3, 4):
        open_ticket_locations[severity] = get_open_ticket_loc_by_severity(db, severity)
    running_ips = get_running_ips(db)
    host_locations = get_host_locations(db)
    logger.info("done with db queries")
    data_file_list = []

    for (output_file, json_data) in [
        (TICKET_COUNT_FILENAME, ticket_severity_counts),
        (OVERALL_METRICS_FILENAME, overall_metrics),
        (TALLY_COUNT_FILENAME, tally_details),
        (OPEN_TICKET_LOCATIONS_FILENAME, open_ticket_locations[0]),
        (OPEN_TICKET_LOCATIONS_1_FILENAME, open_ticket_locations[1]),
        (OPEN_TICKET_LOCATIONS_2_FILENAME, open_ticket_locations[2]),
        (OPEN_TICKET_LOCATIONS_3_FILENAME, open_ticket_locations[3]),
        (OPEN_TICKET_LOCATIONS_4_FILENAME, open_ticket_locations[4]),
        (RUNNING_IPS_FILENAME, running_ips),
        (HOST_LOCATIONS_FILENAME, host_locations),
    ]:
        with open(output_file, "wb") as out:
            out.write(
                json.dumps(json_data, sort_keys=True, default=util.custom_json_handler)
            )
            logger.info(" output file written: {!s}".format(output_file))
            data_file_list.append(output_file)
    execute(push_data, data_file_list, DESTINATION_DIR, hosts=DESTINATION_HOSTS)


def main():
    global __doc__
    __doc__ = re.sub("COMMAND_NAME", __file__, __doc__)
    args = docopt(__doc__, version="v0.0.1")
    db = database.db_from_config(args["--section"])
    # import IPython; IPython.embed() #<<< BREAKPOINT >>>

    generate_push_data_files(db)  # Initial call
    logger.info("scheduled refresh interval: {!s} seconds".format(REFRESH_INTERVAL))
    schedule.every(REFRESH_INTERVAL).seconds.do(generate_push_data_files, db)

    logger.info("starting scheduler loop")
    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == "__main__":
    main()
