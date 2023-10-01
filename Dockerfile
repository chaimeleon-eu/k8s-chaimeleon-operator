FROM python:3.10
ARG kopf_version='1.36.2'

#RUN apt-get update && apt-get install -y python3 python3-pip
RUN pip --no-cache-dir install kopf==${kopf_version}
RUN pip --no-cache-dir install pykube-ng requests kubernetes certbuilder guacli

#RUN apt-get update && apt-get install -y --no-install-recommends ntp

ARG MAIN_DIR="/chaimeleon-operator"
COPY chaimeleon-operator.py VERSION ${MAIN_DIR}/

WORKDIR ${MAIN_DIR}
CMD kopf run chaimeleon-operator.py --all-namespaces --verbose --liveness=http://0.0.0.0:8080/healthz
