#!/usr/bin/env python
"""NCATS web data server.

Usage:
  ncats-webd [options]
  ncats-webd (-h | --help | --version)

Options:
  -d --debug                     Enable debug logging.
  -l --local                     Enable local development mode.
  -h --help                      Show this screen.
  -k --secret-key=KEY_FILE       Secret key used to secure cookies.
  -c --config=CONFIG_FILE        Configuration file to use.
  -s --section=SECTION           Configuration section to use.
  -n --new_hire_section=HIRE_SECTION  Configuration new hire section.
  --version                      Show version.

"""
from gevent import monkey

monkey.patch_all()
async_mode = "gevent"

from docopt import docopt
import os, shlex, subprocess


def main():
    global __doc__
    args = docopt(__doc__, version="v0.0.2")

    command = "gunicorn --bind '[::]:5000' --log-level=debug --timeout=90 -k {!s} --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker -w 1 \"".format(
        async_mode
    )
    command += "ncats_webd.ncats_webd:create_app("

    arg_list = []
    arg_list.append("async_mode='" + async_mode + "'")
    if args["--debug"]:
        arg_list.append("debug=" + str(args["--debug"]))
    if args["--local"]:
        arg_list.append("local=" + str(args["--local"]))
    if args["--secret-key"]:
        arg_list.append("secret_key='" + args["--secret-key"] + "'")
    if args["--config"]:
        arg_list.append("config_filename='" + args["--config"] + "'")
    if args["--section"]:
        arg_list.append("section='" + args["--section"] + "'")
    if args["--new_hire_section"]:
        arg_list.append("new_hire_section='" + args["--new_hire_section"] + "'")
    command += ",".join(arg_list) + ')"'

    if args["--debug"]:
        print("Launching %s" % command)
    server_pid = subprocess.Popen(args=shlex.split(command))
    server_pid.wait()


if __name__ == "__main__":
    main()
