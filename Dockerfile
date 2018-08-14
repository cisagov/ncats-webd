FROM dhub.ncats.cyber.dhs.gov:5001/cyhy-core
MAINTAINER Adam M. Brown <adam.brown@hq.dhs.gov>
ENV CYHY_VAR="/var/cyhy" \
    NCATS_WEBD_DATA_SERVER_SRC="/usr/src/ncats-webd"

USER root
WORKDIR ${NCATS_WEBD_DATA_SERVER_SRC}

COPY . ${NCATS_WEBD_DATA_SERVER_SRC}
RUN pip install --no-cache-dir -r requirements.txt && \
    mkdir -p ${CYHY_VAR}/web && \
    chown -R cyhy:cyhy ${CYHY_VAR} && \
    head -c 24 /dev/urandom > ${CYHY_VAR}/web/secret_key

USER cyhy
WORKDIR ${CYHY_HOME}

EXPOSE 5000
ENTRYPOINT ["ncats-webd"]
