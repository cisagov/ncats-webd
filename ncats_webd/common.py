__ALL__ = ['cache', 'socketio', 'catch_exceptions']

from flask_caching import Cache
from flask_socketio import SocketIO
import functools
import sys, logging # flask_cache handler

def add_flask_cache_handler():
    # get flask_cache logger
    flask_cache_logger = logging.getLogger('flask_cache')
    # set up a handler
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    # add the handler
    flask_cache_logger.addHandler(stderr_handler)

#TODO move cache to instance dir
cache = Cache(config={'CACHE_TYPE': 'filesystem', 'CACHE_DIR' : '/var/cyhy/web/c.cache'})
add_flask_cache_handler()
socketio = SocketIO()

def catch_exceptions(job_func):
    @functools.wraps(job_func)
    def wrapper(*args, **kwargs):
        try:
            job_func(*args, **kwargs)
        except:
            import traceback
            print(traceback.format_exc())
    return wrapper
