"""
FEMA Region Details.

Usage:
  COMMAND_NAME [--section SECTION]
  COMMAND_NAME (-h | --help)
  COMMAND_NAME --version

Options:
  -h --help                      Show this screen.
  --version                      Show version.
  -s SECTION --section=SECTION   Configuration section to use.
"""

import re
import sys
from docopt import docopt
import datetime
from cyhy.db import database
from dateutil import parser
from cyhy.util import util
import StringIO


def build_customer_sector_map(db):
    customer_sector_map = dict()
    CI_parent_node = db.RequestDoc.find_one({"_id": "CRITICAL_INFRASTRUCTURE"})
    if CI_parent_node:
        for CI_sector in CI_parent_node.get("children"):
            for CI_org in db.RequestDoc.get_all_descendants(CI_sector):
                customer_sector_map[CI_org] = CI_sector
    else:
        print "WARNING: No CRITICAL_INFRASTRUCTURE request document found in DB!"

    for org_type in ("PRIVATE", "STATE", "LOCAL", "TRIBAL", "TERRITORIAL"):
        for org in db.RequestDoc.get_all_descendants(org_type):
            if not customer_sector_map.get(org):
                customer_sector_map[org] = org_type

    return customer_sector_map


def fema_detail(db):
    customer_sector_map = build_customer_sector_map(db)
    i_num = (
        ii_num
    ) = iii_num = iv_num = v_num = vi_num = vii_num = viii_num = ix_num = x_num = 0
    customers = db.RequestDoc.find({"stakeholder": True})
    fema_list = []
    for customer in customers:
        try:
            state = customer["agency"]["location"]["state"]
        except:
            state = None
        if state in ["AK", "WA", "OR", "ID"]:
            x_num += 1
        elif state in [
            "UM",
            "PW",
            "FM",
            "MP",
            "AS",
            "MH",
            "GU",
            "HI",
            "CA",
            "NV",
            "AZ",
        ]:
            ix_num += 1
        elif state in ["MT", "ND", "SD", "WY", "UT", "CO"]:
            viii_num += 1
        elif state in ["NE", "IA", "KS", "MO"]:
            vii_num += 1
        elif state in ["NM", "TX", "OK", "AR", "LA"]:
            vi_num += 1
        elif state in ["MN", "WI", "IL", "IN", "MI", "OH"]:
            v_num += 1
        elif state in ["KY", "TN", "NC", "SC", "MS", "AL", "GA", "FL"]:
            iv_num += 1
        elif state in ["PA", "WV", "MD", "DE", "VA", "DC"]:
            iii_num += 1
        elif state in ["NY", "NJ", "PR", "VI"]:
            ii_num += 1
        elif state in ["CT", "RI", "MA", "VT", "NH", "ME"]:
            i_num += 1

        region = get_region(customer)
        name = customer["agency"]["name"].replace(",", "-")
        acronym = customer["_id"]
        sector = get_sector(db, customer, customer_sector_map)
        try:
            city = customer["agency"]["location"]["name"]
            state = customer["agency"]["location"]["state"]
        except:
            city = "N/A"
            state = "N/A"
        try:
            reports = (
                db.reports.find({"owner": customer["_id"]})
                .sort([("generated_time", 1)])
                .limit(1)
            )
            first_scan = reports[0]["generated_time"].strftime("%m/%d/%y")
        except:
            first_scan = "No Reports"

        fema_list.append((region, name, sector, city, state, first_scan, acronym))

    fema_list.sort(key=lambda tup: tup[0])
    fema_list.insert(
        0,
        (
            i_num,
            ii_num,
            iii_num,
            iv_num,
            v_num,
            vi_num,
            vii_num,
            viii_num,
            ix_num,
            x_num,
        ),
    )
    return fema_list


def get_region(customer):
    try:
        state = customer["agency"]["location"]["state"]
    except:
        region = "No Location"
    if state in ["AK", "WA", "OR", "ID"]:
        region = 10
    elif state in ["UM", "PW", "FM", "MP", "AS", "MH", "GU", "HI", "CA", "NV", "AZ"]:
        region = 9
    elif state in ["MT", "ND", "SD", "WY", "UT", "CO"]:
        region = 8
    elif state in ["NE", "IA", "KS", "MO"]:
        region = 7
    elif state in ["NM", "TX", "OK", "AR", "LA"]:
        region = 6
    elif state in ["MN", "WI", "IL", "IN", "MI", "OH"]:
        region = 5
    elif state in ["KY", "TN", "NC", "SC", "MS", "AL", "GA", "FL"]:
        region = 4
    elif state in ["PA", "WV", "MD", "DE", "VA", "DC"]:
        region = 3
    elif state in ["NY", "NJ", "PR", "VI"]:
        region = 2
    elif state in ["CT", "RI", "MA", "VT", "NH", "ME"]:
        region = 1
    else:
        region = "N/A"
    return region


def get_sector(db, customer, customer_sector_map):
    customer_sector = customer_sector_map.get(customer["_id"])

    if customer_sector:
        if customer_sector == "CI_CHEMICAL":
            sector = "CI - Chemical"
        elif customer_sector == "CI_COMMERCIAL_FACILITIES":
            sector = "CI - Commercial Facilities"
        elif customer_sector == "CI_COMMUNICATIONS":
            sector = "CI - Communications"
        elif customer_sector == "CI_CRITICAL_MANUFACTURING":
            sector = "CI - Critical Mfg"
        elif customer_sector == "CI_DAMS":
            sector = "CI - Dams"
        elif customer_sector == "CI_DEFENSE_INDUSTRIAL_BASE":
            sector = "CI - Def Industrial Base"
        elif customer_sector == "CI_EMERGENCY_SERVICES":
            sector = "CI - Emergency Services"
        elif customer_sector == "CI_ENERGY":
            sector = "CI - Energy"
        elif customer_sector == "CI_FINANCIAL_SERVICES":
            sector = "CI - Fin Serv"
        elif customer_sector == "CI_FOOD_AND_AGRICULTURE":
            sector = "CI - Food & Ag"
        elif customer_sector == "CI_GOVERNMENT_FACILITIES":
            sector = "CI - Govt Facilities"
        elif customer_sector == "CI_HEALTHCARE_AND_PUBLIC_HEALTH":
            sector = "CI - Pub Health"
        elif customer_sector == "CI_INFORMATION_TECHNOLOGY":
            sector = "CI - Information Tech"
        elif customer_sector == "CI_NUCLEAR_REACTORS_MATERIALS_AND_WASTE":
            sector = "CI - Nuclear Mat. & Waste"
        elif customer_sector == "CI_TRANSPORTATION_SYSTEMS":
            sector = "CI - Transportation"
        elif customer_sector == "CI_WATER_AND_WASTEWATER_SYSTEMS":
            sector = "CI - Water"
        elif customer_sector == "PRIVATE":
            sector = "Private"
        elif customer_sector == "STATE":
            sector = "State"
        elif customer_sector == "LOCAL":
            sector = "Local"
        elif customer_sector == "TRIBAL":
            sector = "Tribal"
        elif customer_sector == "TERRITORIAL":
            sector = "Territorial"
    else:
        sector = "N/A"
    return sector


def fema_csv(db):
    output = StringIO.StringIO()
    customers = db.RequestDoc.find({"stakeholder": True})
    customer_sector_map = build_customer_sector_map(db)
    for customer in customers:
        name = customer["agency"]["name"].replace(",", "-")
        acronym = customer["_id"]
        region = get_region(customer)
        sector = get_sector(db, customer, customer_sector_map)
        try:
            city = customer["agency"]["location"]["name"]
            state = customer["agency"]["location"]["state"]
        except:
            city = "N/A"
            state = "N/A"
        try:
            reports = (
                db.reports.find({"owner": customer["_id"]})
                .sort([("generated_time", 1)])
                .limit(1)
            )
            first_scan = reports[0]["generated_time"].strftime("%m/%d/%y")
        except:
            first_scan = "No Reports"

        output.write(
            str(region)
            + ","
            + name
            + ","
            + sector
            + ","
            + city
            + ","
            + state
            + ","
            + str(first_scan)
            + "\n"
        )

    return output


def main():
    global __doc__
    __doc__ = re.sub("COMMAND_NAME", __file__, __doc__)
    args = docopt(__doc__, version="v0.0.1")
    db = database.db_from_config(args["--section"])

    print fema_csv(db).getvalue()
