FROM python:3.10
ARG kopf_version='1.36.0'

#RUN apt-get update && apt-get install -y python3 python3-pip
RUN pip --no-cache-dir install kopf==${kopf_version}
RUN pip --no-cache-dir install pykube-ng requests kubernetes certbuilder guacli

#RUN apt-get update && apt-get install -y --no-install-recommends ntp
ADD chaimeleon-operator.py /chaimeleon-operator/chaimeleon-operator.py

CMD kopf run /chaimeleon-operator/chaimeleon-operator.py --all-namespaces --verbose --liveness=http://0.0.0.0:8080/healthz
