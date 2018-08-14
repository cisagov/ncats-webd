from setuptools import setup, find_packages

setup(
    name='ncats-webd',
    version='0.0.2',
    author='Mark Feldhousen Jr.',
    author_email='mark.feldhousen@hq.dhs.gov',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    entry_points={
        'console_scripts': [
          'ncats-webd=ncats_webd.launch:main',
        ],
    },
    #url='http://pypi.python.org/pypi/CyHy/',
    license='LICENSE.txt',
    description='Web Data for Cyber Hygiene',
    #long_description=open('README.txt').read(),
    install_requires=[
        "cyhy-core >= 0.0.2",
        "numpy >= 1.7.1",
        "python-dateutil >= 2.2",
        "netaddr >= 0.7.10",
        "pandas == 0.19.2",
        "docopt >= 0.6.2",
        "flask >= 0.10.1",
        "Flask-Caching >= 1.4.0",
        "Flask-Uploads >= 0.2.0",
        "Flask-SocketIO >= 2.1",
        "Flask-Cors >= 2.1.0",
        "schedule >= 0.3.2",
        "gunicorn >= 19.6.0",
        "gevent >= 1.2.0",
        "gevent-websocket >= 0.9.5",
	"ipython",
    ]
)
