# NCATS-WebD(aemon) #

[![GitHub Build Status](https://github.com/cisagov/ncats-webd/workflows/build/badge.svg)](https://github.com/cisagov/ncats-webd/actions)
[![Coverage Status](https://coveralls.io/repos/github/cisagov/ncats-webd/badge.svg?branch=develop)](https://coveralls.io/github/cisagov/ncats-webd?branch=develop)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/cisagov/ncats-webd.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/ncats-webd/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/cisagov/ncats-webd.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/ncats-webd/context:python)
[![Language grade: JavaScript](https://img.shields.io/lgtm/grade/javascript/g/cisagov/ncats-webd.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/ncats-webd/context:javascript)
[![Known Vulnerabilities](https://snyk.io/test/github/cisagov/ncats-webd/develop/badge.svg)](https://snyk.io/test/github/cisagov/ncats-webd)

## Getting Started ##

```console
git clone git@github.com:jsf9k/ncats-webd.git
cd ncats-webd
docker build -t ncats-webd .
```

## Developing and Testing with Docker ##

The fastest way to get started developing and testing will be to use docker. The
following will start a development server and expose it at
`http://localhost:5000`.

**_Starting Development Server_**

```console
docker run -d --name ncats-webd -v /private/etc/cyhy:/etc/cyhy -v $(pwd)/ncats_webd:/usr/src/ncats-webd/ncats_webd -p 5000:5000 ncats-webd -dls <db-section>
```

When changes have been made to your code, you'll need to restart the server.

**_Restarting Development Server_**

```console
docker restart ncats-webd
```

When you are finished developing stop the development server.

**_Stopping Development Server_**

```console
docker stop ncats-webd
```

If you are finished with the project, you can clean up all images with the
following:

**_Cleaning Up_**

```console
docker rm ncats-webd
```

### Build for Staging ###

Use Jenkins to build the image. To deploy, see below.

**_Deploy to Staging_**

```console
c4b1 $ docker service update --image dhub.ncats.dhs.gov:5001/ncats-webd:staging
```

### Build for Production ###

**_Deploy to Production_**

```console
# Local Machine

localhost $ hg tags
tip                               82:42437018e850
2.0.8                             78:b42d84666d2c
2.0.7                             74:131e0ed8b1f6
2.0.6                             68:9294b54de319

localhost $ hg tag 2.0.9
localhost $ hg push
```

```console
# Staging Swarm Manager

c4b1 $ docker pull dhub.ncats.dhs.gov:5001/ncats-webd:staging
c4b1 $ docker tag dhub.ncats.dhs.gov:5001/ncats-webd:staging dhub.ncats.dhs.gov:5001/ncats-webd:stable
c4b1 $ docker tag dhub.ncats.dhs.gov:5001/ncats-webd:staging dhub.ncats.dhs.gov:5001/ncats-webd:2.0.9
c4b1 $ docker push dhub.ncats.dhs.gov:5001/ncats-webd
```

```console
# Production Swarm Manager

c2b2 $ docker pull dhub.ncats.dhs.gov:5001/ncats-webd:stable

c2b2 $ docker stack ls
NAME         SERVICES
cyhy-pusher  2
web-stack    3

c2b2 $ docker stack ps web-stack
ID            NAME                       IMAGE                                       NODE  DESIRED STATE  CURRENT STATE            ERROR                      PORTS
5xv3oooffrrv  web-stack_api.1            dhub.ncats.dhs.gov:5001/ncats-webd:stable   c3b4  Running        Running 29 seconds ago
m9vdh3r353vl  web-stack_interface.1      dhub.ncats.dhs.gov:5001/ncats-webui:stable  c2b2  Running        Running 3 days ago
q2j1gemuruyl  web-stack_proxy.1          nginx:1-alpine                              c3b4  Running        Running 5 weeks ago

c2b2 $ docker service update --image dhub.ncats.dhs.gov:5001/ncats-webd:stable web-stack_api
```

## Contributing ##

We welcome contributions!  Please see [`CONTRIBUTING.md`](CONTRIBUTING.md) for
details.

## License ##

This project is in the worldwide [public domain](LICENSE).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
