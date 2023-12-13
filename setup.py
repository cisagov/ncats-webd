from setuptools import setup, find_packages

setup(
    name="ncats-webd",
    version="0.0.2",
    author="Mark Feldhousen Jr.",
    author_email="mark.feldhousen@cisa.dhs.gov",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    entry_points={"console_scripts": ["ncats-webd=ncats_webd.launch:main",],},
    # url='http://pypi.python.org/pypi/CyHy/',
    license="LICENSE.txt",
    description="Web Data for Cyber Hygiene",
    # long_description=open('README.txt').read(),
    install_requires=[
        "cffi >= 1.12.2",
        "cyhy-core >= 0.0.2",
        "docopt >= 0.6.2",
        "flask >= 0.10.1",
        "Flask-Caching >= 1.4.0, < 1.8.0",
        # The Flask-Cors package no longer support Python 2 as of version 4.0.0.
        # However, the build process for the package is still producing wheels that
        # are marked for Python 2 support. Please see the following issue for more
        # information: https://github.com/corydolphin/flask-cors/issues/339
        "Flask-Cors >= 2.1.0, < 4",
        "Flask-SocketIO >= 2.1, < 5",
        "Flask-Uploads >= 0.2.0",
        "gevent >= 1.2.0",
        "gevent-websocket >= 0.9.5",
        "greenlet < 2",
        "gunicorn >= 19.6.0",
        "ipython",
        "netaddr >= 0.7.10",
        "numpy == 1.16.2",
        "pandas == 0.23.3",
        "python-dateutil >= 2.2",
        "python-engineio >= 3, < 3.14",
        "schedule >= 0.3.2",
    ],
)
