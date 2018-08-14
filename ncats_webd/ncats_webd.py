#!/usr/bin/env python

import os
import sys
import re
from threading import Thread
import time

from flask import Flask, current_app
from flask_cors import CORS
import schedule
import logging

from cyhy.core import *
from cyhy.db import database
from common import cache, socketio

def create_app(debug=None, local=None, secret_key=None, async_mode='gevent', config_filename=None, section=None, new_hire_section=None):
    app = Flask(__name__, instance_path='/var/cyhy/web')
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
    cache.init_app(app)
    socketio.init_app(app, async_mode=async_mode)
    install_secret_key(app, secret_key)
    register_blueprints(app)
    using_yaml = str(config_filename).lower().endswith(('.yml', '.yaml'))
    app.db = database.db_from_config(section, config_filename=config_filename, yaml=using_yaml)
    # TODO add exception handler for no new_hire_section
    app.new_hire_db = database.db_from_config(new_hire_section, config_filename=config_filename, yaml=using_yaml)
    app.logger.debug(app.new_hire_db)
    app.logger.debug(app.db)
    start_scheduler(app)
    # TODO set origins via environment variables
    origins = [".*[\.]?data\.ncats\.dhs\.gov"]
    if local: origins.append("^.*\/\/localhost(:[0-9]+)?$")
    print origins
    CORS(app, resources={r"\/.*": {"origins": origins}})
    # import IPython; IPython.embed() #<<< BREAKPOINT >>>
    # app.run(host='::', debug, threaded=True)
    app.config['DEBUG'] = debug


    return app

def install_secret_key(app, filename):
    """Configure the SECRET_KEY from a file
    in the instance directory.

    If the file does not exist, print instructions
    to create it from a shell with a random key,
    then exit.
    """
    if filename == None:
        filename = os.path.join(app.instance_path, 'secret_key')
    try:
        app.config['SECRET_KEY'] = open(filename, 'rb').read()
    except IOError:
        print >> sys.stderr, 'Error: No secret key. Create it with:'
        print >> sys.stderr, 'head -c 24 /dev/urandom >', filename
        sys.exit(1)

def register_blueprints(app):
    from blueprints.welcome import welcome
    app.register_blueprint(welcome.bp)
    from blueprints.status import status
    app.register_blueprint(status.bp, url_prefix='/status')
    from blueprints.history import history
    app.register_blueprint(history.bp, url_prefix='/history')
    from blueprints.maps import maps
    app.register_blueprint(maps.bp, url_prefix='/maps')
    from blueprints.metrics import metrics
    app.register_blueprint(metrics.bp, url_prefix='/metrics')
    from blueprints.dashboard import dashboard
    app.register_blueprint(dashboard.bp, url_prefix='/dashboard')
    # from blueprints.bod import bod
    # app.register_blueprint(bod.bp, url_prefix='/bod')
    from blueprints.queues import queues
    app.register_blueprint(queues.bp, url_prefix='/queues')
    from blueprints.cybex import cybex
    app.register_blueprint(cybex.bp, url_prefix='/cybex')
    from blueprints.stakeholders import stakeholders
    app.register_blueprint(stakeholders.bp, url_prefix='/stakeholders')
    from blueprints.hiringdashboard import hiringdashboard
    app.register_blueprint(hiringdashboard.bp, url_prefix="/hiringdashboard")

def start_scheduler(app):
    def scheduler_loop(app):
        # run scheduler within the app context so jobs have access to caches, etc...
        with app.app_context():
            app.logger.debug('scheduler daemon thread started')
            current_app.logger.debug('scheduler daemon thread started')
            while True:
                schedule.run_pending()
                time.sleep(1)
    thready = Thread(target=scheduler_loop, kwargs={'app':app},)
    thready.daemon = True
    thready.start()
