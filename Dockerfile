FROM python:3.7
LABEL maintainer=serlohu@upv.es
ARG kopf_version='1.35.4'


#RUN apt-get update && apt-get install -y python3 python3-pip
RUN pip install kopf==${kopf_version}
RUN pip install pykube-ng
RUN pip install requests
RUN pip install pyyaml
RUN pip3 install kubernetes 
RUN pip install certbuilder

#RUN apt-get update && apt-get install -y --no-install-recommends ntp
ADD chaimeleon-operator.py /chaimeleon-operator/chaimeleon-operator.py

CMD kopf run /chaimeleon-operator/chaimeleon-operator.py --verbose --liveness=http://0.0.0.0:8080/healthz