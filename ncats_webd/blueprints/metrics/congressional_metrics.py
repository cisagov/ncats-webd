#!/usr/bin/env python

"""Report on metrics requested by Congress (see OPS-1600 for details)

Usage:
  COMMAND_NAME [--section SECTION] START_DATE [END_DATE]
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
import netaddr
from datetime import datetime, timedelta
from dateutil import parser, relativedelta
from cyhy.core.common import AGENCY_TYPE
from cyhy.db import database
from cyhy.util import util
from collections import defaultdict
from pandas import DataFrame, isnull


def tickets_opened_count_pl(org_list, start_date, end_date):
    return (
        [
            {
                "$match": {
                    "source": "nessus",
                    "false_positive": False,
                    "owner": {"$in": org_list},
                    "time_opened": {"$gte": start_date, "$lt": end_date},
                }
            },
            {
                "$group": {
                    "_id": {},
                    "low": {
                        "$sum": {"$cond": [{"$eq": ["$details.severity", 1]}, 1, 0]}
                    },
                    "medium": {
                        "$sum": {"$cond": [{"$eq": ["$details.severity", 2]}, 1, 0]}
                    },
                    "high": {
                        "$sum": {"$cond": [{"$eq": ["$details.severity", 3]}, 1, 0]}
                    },
                    "critical": {
                        "$sum": {"$cond": [{"$eq": ["$details.severity", 4]}, 1, 0]}
                    },
                    "total": {"$sum": 1},
                }
            },
        ],
        database.TICKET_COLLECTION,
    )


# def open_ticket_count_pl(org_list, start_date, end_date):
#     return [
#            {'$match': {'open':True, 'source': 'nessus', 'false_positive':False, 'owner':{'$in':org_list},
#                        'time_opened':{'$gte':start_date, '$lt':end_date}}
#                       },
#            {'$group': {'_id': {},
#                        'low':{'$sum':{'$cond':[{'$eq':['$details.severity',1]}, 1, 0]}},
#                        'medium':{'$sum':{'$cond':[{'$eq':['$details.severity',2]}, 1, 0]}},
#                        'high':{'$sum':{'$cond':[{'$eq':['$details.severity',3]}, 1, 0]}},
#                        'critical':{'$sum':{'$cond':[{'$eq':['$details.severity',4]}, 1, 0]}},
#                        'total':{'$sum':1},
#                        }
#             }
#             ], database.TICKET_COLLECTION


def closed_ticket_count_pl(org_list, start_date, end_date):
    return (
        [
            {
                "$match": {
                    "open": False,
                    "source": "nessus",
                    "false_positive": False,
                    "owner": {"$in": org_list},
                    "time_closed": {"$gte": start_date, "$lt": end_date},
                }
            },
            {
                "$group": {
                    "_id": {},
                    "low": {
                        "$sum": {"$cond": [{"$eq": ["$details.severity", 1]}, 1, 0]}
                    },
                    "medium": {
                        "$sum": {"$cond": [{"$eq": ["$details.severity", 2]}, 1, 0]}
                    },
                    "high": {
                        "$sum": {"$cond": [{"$eq": ["$details.severity", 3]}, 1, 0]}
                    },
                    "critical": {
                        "$sum": {"$cond": [{"$eq": ["$details.severity", 4]}, 1, 0]}
                    },
                    "total": {"$sum": 1},
                }
            },
        ],
        database.TICKET_COLLECTION,
    )


def opened_in_date_range_open_ticket_age_pl(org_list, start_date, end_date):
    return (
        [
            {
                "$match": {
                    "$or": [
                        {
                            "open": True,
                            "source": "nessus",
                            "false_positive": False,
                            "owner": {"$in": org_list},
                            "time_opened": {"$gte": start_date, "$lt": end_date},
                        },
                        {
                            "open": False,
                            "source": "nessus",
                            "false_positive": False,
                            "owner": {"$in": org_list},
                            "time_opened": {"$gte": start_date, "$lt": end_date},
                            "time_closed": {"$gte": end_date},
                        },
                    ]
                }
            },
            {
                "$project": {
                    "severity": "$details.severity",
                    "open_ticket_duration": {"$subtract": [end_date, "$time_opened"]},
                }
            },
        ],
        database.TICKET_COLLECTION,
    )


def closed_in_date_range_closed_ticket_age_pl(org_list, start_date, end_date):
    return (
        [
            {
                "$match": {
                    "open": False,
                    "source": "nessus",
                    "false_positive": False,
                    "owner": {"$in": org_list},
                    "time_closed": {"$gte": start_date, "$lt": end_date},
                },
            },
            {
                "$project": {
                    "severity": "$details.severity",
                    "duration_to_close": {
                        "$subtract": ["$time_closed", "$time_opened"]
                    },
                }
            },
        ],
        database.TICKET_COLLECTION,
    )


# def opened_in_date_range_closed_ticket_age_pl(org_list, start_date, end_date):
#     return [
#            {'$match': {'open':False, 'source': 'nessus', 'false_positive':False, 'owner':{'$in':org_list},
#                        'time_opened':{'$gte':start_date, '$lt':end_date}},
#                         },
#            {'$project': {'severity':'$details.severity',
#                          'duration_to_close':{'$subtract': ['$time_closed', '$time_opened']}}
#                         }
#            ], database.TICKET_COLLECTION


def run_pipeline((pipeline, collection), db):
    results = db[collection].aggregate(
        pipeline, allowDiskUse=True, explain=True, cursor={}
    )


def congressional_data(db, start_date, end_date):
    if start_date == None:
        return "Must input a start date. Received %s & %s" % (start_date, end_date)
    if end_date == None:
        end_date = util.utcnow()

    # Needed when run as a standalone script:
    # start_date = parser.parse(start_date)
    # end_date = parser.parse(end_date)

    all_stakeholders = db.RequestDoc.get_owner_types(
        as_lists=True, stakeholders_only=True
    )

    active_fed_stakeholders = db.ReportDoc.find(
        {
            "owner": {"$in": all_stakeholders[AGENCY_TYPE.FEDERAL]},
            "generated_time": {"$gte": start_date, "$lt": end_date},
        }
    ).distinct("owner")
    active_fed_stakeholders.sort()
    active_fed_owners = list()
    for org in active_fed_stakeholders:
        active_fed_owners.append(org)
        active_fed_owners += db.RequestDoc.get_all_descendants(org)

    fed_executive_stakeholders = db.RequestDoc.get_by_owner("EXECUTIVE")["children"]
    active_fed_executive_stakeholders = db.ReportDoc.find(
        {
            "owner": {"$in": fed_executive_stakeholders},
            "generated_time": {"$gte": start_date, "$lt": end_date},
        }
    ).distinct("owner")
    active_fed_executive_stakeholders.sort()
    active_fed_executive_owners = list()
    for org in active_fed_executive_stakeholders:
        active_fed_executive_owners.append(org)
        active_fed_executive_owners += db.RequestDoc.get_all_descendants(org)

    fed_cfo_stakeholders = db.RequestDoc.get_by_owner("FED_CFO_ACT")["children"]
    active_fed_cfo_stakeholders = db.ReportDoc.find(
        {
            "owner": {"$in": fed_cfo_stakeholders},
            "generated_time": {"$gte": start_date, "$lt": end_date},
        }
    ).distinct("owner")
    active_fed_cfo_stakeholders.sort()
    active_fed_cfo_owners = list()
    for org in active_fed_cfo_stakeholders:
        active_fed_cfo_owners.append(org)
        active_fed_cfo_owners += db.RequestDoc.get_all_descendants(org)

    fed_exec_non_cfo_stakeholders = list(
        set(fed_executive_stakeholders) - set(fed_cfo_stakeholders)
    )
    active_fed_exec_non_cfo_stakeholders = db.ReportDoc.find(
        {
            "owner": {"$in": fed_exec_non_cfo_stakeholders},
            "generated_time": {"$gte": start_date, "$lt": end_date},
        }
    ).distinct("owner")
    active_fed_exec_non_cfo_stakeholders.sort()
    active_fed_exec_non_cfo_owners = list()
    for org in active_fed_exec_non_cfo_stakeholders:
        active_fed_exec_non_cfo_owners.append(org)
        active_fed_exec_non_cfo_owners += db.RequestDoc.get_all_descendants(org)

    SLTT_stakeholders = (
        all_stakeholders[AGENCY_TYPE.STATE]
        + all_stakeholders[AGENCY_TYPE.LOCAL]
        + all_stakeholders[AGENCY_TYPE.TRIBAL]
        + all_stakeholders[AGENCY_TYPE.TERRITORIAL]
    )
    active_SLTT_stakeholders = db.ReportDoc.find(
        {
            "owner": {"$in": SLTT_stakeholders},
            "generated_time": {"$gte": start_date, "$lt": end_date},
        }
    ).distinct("owner")
    # active_SLTT_stakeholders.sort()
    # active_SLTT_owners = list()
    # for org in active_SLTT_stakeholders:
    #     active_SLTT_owners.append(org)
    #     active_SLTT_owners += db.RequestDoc.get_all_descendants(org)

    active_private_stakeholders = db.ReportDoc.find(
        {
            "owner": {"$in": all_stakeholders[AGENCY_TYPE.PRIVATE]},
            "generated_time": {"$gte": start_date, "$lt": end_date},
        }
    ).distinct("owner")
    # active_private_stakeholders.sort()
    # active_private_owners = list()
    # for org in active_private_stakeholders:
    #     active_private_owners.append(org)
    #     active_private_owners += db.RequestDoc.get_all_descendants(org)

    print "Congressional Cyber Hygiene Metrics Report"
    mylist = {}
    print "Date Range: {} - {}".format(
        start_date.strftime("%Y-%m-%d %H:%M UTC"),
        end_date.strftime("%Y-%m-%d %H:%M UTC"),
    )

    print "\n--------------------------------------------------"
    print "Critical Vulnerability Remediation Performance:\n"
    # Use "_owners" lists here because we DO want to include descendent orgs in these metrics
    for (stakeholder_list, group_name) in (
        (active_fed_owners, "FEDERAL"),
        (active_fed_executive_owners, "FEDERAL EXECUTIVE"),
        (active_fed_cfo_owners, "FEDERAL EXECUTIVE - CFO ACT"),
        (active_fed_exec_non_cfo_owners, "FEDERAL EXECUTIVE - NON-CFO ACT"),
    ):
        print "{}:".format(group_name)
        (pipeline, collection) = closed_in_date_range_closed_ticket_age_pl(
            stakeholder_list, start_date, end_date
        )
        output = db[collection].aggregate(pipeline, cursor={})
        df = DataFrame(list(output))
        median_days_to_mitigate_criticals = round(
            df.loc[df["severity"] == 4]["duration_to_close"].median()
            / (24 * 60 * 60 * 1000.0)
        )
        if isnull(median_days_to_mitigate_criticals):
            print "  Median time to mitigate Critical vulnerabilities: No Critical vulnerabilities mitigated"
            myarg = {
                group_name.replace(" ", "_").replace("-", "_")
                + "_median_time_to_mitigate": "No Critical Vulnerabilities Mitigated"
            }
        else:
            print "  Median time to mitigate Critical vulnerabilities: {0:,g} days".format(
                median_days_to_mitigate_criticals
            )
            myarg = {
                group_name.replace(" ", "_").replace("-", "_")
                + "_median_time_to_mitigate": "{0:,g}".format(
                    median_days_to_mitigate_criticals
                )
            }
        mylist.update(myarg)

        (pipeline, collection) = opened_in_date_range_open_ticket_age_pl(
            stakeholder_list, start_date, end_date
        )
        output = db[collection].aggregate(pipeline, cursor={})
        df = DataFrame(list(output))
        median_days_active_criticals = round(
            df.loc[df["severity"] == 4]["open_ticket_duration"].median()
            / (24 * 60 * 60 * 1000.0)
        )
        if isnull(median_days_active_criticals):
            print "  Median time Critical vulnerabilities currently active: No Critical vulnerabilities currently active"
            myarg = {
                group_name.replace(" ", "_").replace("-", "_")
                + "_currently_active": "No Critical Vulnerabilities Currently Active"
            }
        else:
            print "  Median time Critical vulnerabilities currently active: {0:,g} days".format(
                median_days_active_criticals
            )
            myarg = {
                group_name.replace(" ", "_").replace("-", "_")
                + "_currently_active": "{0:,g}".format(median_days_active_criticals)
            }
        mylist.update(myarg)
        print

    print "--------------------------------------------------"
    print "Number of Active CyHy Stakeholders by Segment:\n"
    # Use "_stakeholders" lists here because we DO NOT want to include descendent orgs in these metrics
    for (stakeholder_list, group_name) in (
        (active_fed_stakeholders, "FEDERAL"),
        (active_fed_executive_stakeholders, "FEDERAL EXECUTIVE"),
        (active_fed_cfo_stakeholders, "FEDERAL EXECUTIVE - CFO ACT"),
        (active_fed_exec_non_cfo_stakeholders, "FEDERAL EXECUTIVE - NON-CFO ACT"),
        (active_SLTT_stakeholders, "SLTT"),
        (active_private_stakeholders, "PRIVATE"),
    ):
        print "{}: {} stakeholders".format(group_name, len(stakeholder_list))
        myarg = {
            group_name.replace(" ", "_").replace("-", "_")
            + "_active_stakeholders": "{0:,g}".format(len(stakeholder_list))
        }
        mylist.update(myarg)

    print "\n--------------------------------------------------"
    print "Number of New Vulnerabilities Detected:\n"
    # Use "_owners" lists here because we DO want to include descendent orgs in these metrics
    for (stakeholder_list, group_name) in (
        (active_fed_owners, "FEDERAL"),
        (active_fed_executive_owners, "FEDERAL EXECUTIVE"),
        (active_fed_cfo_owners, "FEDERAL EXECUTIVE - CFO ACT"),
        (active_fed_exec_non_cfo_owners, "FEDERAL EXECUTIVE - NON-CFO ACT"),
    ):
        (pipeline, collection) = tickets_opened_count_pl(
            stakeholder_list, start_date, end_date
        )
        output = list(db[collection].aggregate(pipeline, cursor={}))
        print "{}:".format(group_name)
        for i in ("critical", "high", "medium", "low"):
            try:
                print "  {}: {:,}".format(i.title(), output[0][i])
                myarg = {
                    group_name.replace(" ", "_").replace("-", "_")
                    + "_{}_New_Vulns_Detected".format(i.title()): "{:,}".format(
                        output[0][i]
                    )
                }
            except IndexError:
                print "  {}: 0".format(i.title())
                myarg = {
                    group_name.replace(" ", "_").replace("-", "_")
                    + "_{}_New_Vulns_Detected".format(i.title()): "0"
                }
            mylist.update(myarg)
        print

    print "--------------------------------------------------"
    print "Number of Vulnerabilities Mitigated:\n"
    # Use "_owners" lists here because we DO want to include descendent orgs in these metrics
    for (stakeholder_list, group_name) in (
        (active_fed_owners, "FEDERAL"),
        (active_fed_executive_owners, "FEDERAL EXECUTIVE"),
        (active_fed_cfo_owners, "FEDERAL EXECUTIVE - CFO ACT"),
        (active_fed_exec_non_cfo_owners, "FEDERAL EXECUTIVE - NON-CFO ACT"),
    ):
        (pipeline, collection) = closed_ticket_count_pl(
            stakeholder_list, start_date, end_date
        )
        output = list(db[collection].aggregate(pipeline, cursor={}))
        print "{}:".format(group_name)
        for i in ("critical", "high", "medium", "low"):
            try:
                print "  {}: {:,}".format(i.title(), output[0][i])
                myarg = {
                    group_name.replace(" ", "_").replace("-", "_")
                    + "_{}_New_Vulns_Mitigated".format(i.title()): "{:,}".format(
                        output[0][i]
                    )
                }
            except IndexError:
                print "  {}: 0".format(i.title())
                myarg = {
                    group_name.replace(" ", "_").replace("-", "_")
                    + "_{}_New_Vulns_Mitigated".format(i.title()): "0"
                }
            mylist.update(myarg)
        print

    print "=================================================="
    print "Active CyHy Federal Stakeholders:\n"
    # Use "_stakeholders" lists here because we DO NOT want to include descendent orgs in these metrics
    for (stakeholder_list, group_name) in (
        (active_fed_stakeholders, "FEDERAL"),
        (active_fed_executive_stakeholders, "FEDERAL EXECUTIVE"),
        (active_fed_cfo_stakeholders, "FEDERAL EXECUTIVE - CFO ACT"),
        (active_fed_exec_non_cfo_stakeholders, "FEDERAL EXECUTIVE - NON-CFO ACT"),
    ):
        myarg = {
            group_name.replace(" ", "_").replace("-", "_")
            + "_Active_CyHy_Stakeholders": stakeholder_list
        }
        mylist.update(myarg)
        print "{} ({} agencies): ".format(group_name, len(stakeholder_list)),
        for org in stakeholder_list:
            if org != stakeholder_list[-1]:
                print "{},".format(org),
            else:
                print "{}\n".format(org)

    # import IPython; IPython.embed() #<<< BREAKPOINT >>>
    # sys.exit(0)
    print mylist
    return mylist


def main():
    global __doc__
    __doc__ = re.sub("COMMAND_NAME", __file__, __doc__)
    args = docopt(__doc__, version="v0.0.1")
    db = database.db_from_config(args["--section"])
    congressional_data(db, args["START_DATE"], args["END_DATE"])


if __name__ == "__main__":
    main()
