import kopf
import kubernetes
import yaml
import os 
import json
import threading
import os
import requests
import time

__VERSION__ = "1.0.1"

LOCK = None
LOCAL_STORAGE = {}
OPERATOR_SERVICE_ACCOUNT_NAME = None
OPERATOR_SERVICE_ACCOUNT_NAMESPACE = None
KEYCLOAK_CLIENT = None
KEYCLOAK_CLIENT_SECRET = None
KEYCLOAK_ENDPOINT= None
KEYCLOAK_REALM = None
DATASET_SERVICE_ENDPOINT = None

KEYCLOAK_MAX_RETRIES = None
DATASET_SERVICE_MAX_RETRIES = None
DEFAULT_KEYCLOAK_MAX_RETRIES = 10
DEFAULT_DATASET_SERVICE_MAX_RETRIES = 10

K8S_USER_PREFIX=""

@kopf.on.login(retries=3)
def login_fn(**kwargs):
    # Login using the service account that is mounted automatically in the container
    return kopf.login_via_pykube(**kwargs)

@kopf.on.startup()
def config(settings: kopf.OperatorSettings, logger, **_):
    global LOCK, KEYCLOAK_CLIENT, KEYCLOAK_CLIENT_SECRET, KEYCLOAK_ENDPOINT, KEYCLOAK_REALM, DATASET_SERVICE_ENDPOINT, DEFAULT_KEYCLOAK_MAX_RETRIES, KEYCLOAK_MAX_RETRIES, DEFAULT_DATASET_SERVICE_MAX_RETRIES, DATASET_SERVICE_MAX_RETRIES, K8S_USER_PREFIX, OPERATOR_SERVICE_ACCOUNT_NAME, OPERATOR_SERVICE_ACCOUNT_NAMESPACE

    LOCK = threading.RLock()

    # Required ENV vars
    KEYCLOAK_CLIENT = os.getenv('KEYCLOAK_CLIENT')
    KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET')
    KEYCLOAK_ENDPOINT = os.getenv('KEYCLOAK_ENDPOINT')
    KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM')
    DATASET_SERVICE_ENDPOINT = os.getenv('DATASET_SERVICE_ENDPOINT')
    OPERATOR_SERVICE_ACCOUNT_NAME = os.getenv('OPERATOR_SERVICE_ACCOUNT_NAME') 
    OPERATOR_SERVICE_ACCOUNT_NAMESPACE = os.getenv('OPERATOR_SERVICE_ACCOUNT_NAMESPACE')
    

    # Optional ENV vars
    KEYCLOAK_MAX_RETRIES = os.getenv('KEYCLOAK_MAX_RETRIES')
    DATASET_SERVICE_MAX_RETRIES = os.getenv('DATASET_SERVICE_MAX_RETRIES')
    OPERATOR_SERVICE_PORT = int(os.getenv('CHAIMELEON_OPERATOR_SERVICE_PORT'))
    OPERATOR_SERVICE_HOST = str(os.getenv('CHAIMELEON_OPERATOR_SERVICE_HOST'))
    K8S_USER_PREFIX = str(os.getenv('K8S_USER_PREFIX'))

    #logger.info("OPERATOR_SERVICE_PORT=%d" % (OPERATOR_SERVICE_PORT))
    #logger.info("OPERATOR_SERVICE_HOST=%s" % (OPERATOR_SERVICE_HOST))

    if not OPERATOR_SERVICE_PORT or not OPERATOR_SERVICE_HOST:
        raise kopf.PermanentError("You must deploy a service ClusterIP to expose the operator with the name 'chaimeleon-operator' (this operator gets the env variables CHAIMELEON_OPERATOR_SERVICE_HOST and CHAIMELEON_OPERATOR_SERVICE_PORT)")

    settings.admission.server = kopf.WebhookServer(host=OPERATOR_SERVICE_HOST, port=OPERATOR_SERVICE_PORT)
    settings.admission.managed = 'chaimeleon.eu'

    if not KEYCLOAK_CLIENT or not KEYCLOAK_CLIENT_SECRET or not DATASET_SERVICE_ENDPOINT or not KEYCLOAK_ENDPOINT or not KEYCLOAK_REALM or not OPERATOR_SERVICE_ACCOUNT_NAME or not OPERATOR_SERVICE_ACCOUNT_NAMESPACE:
        raise kopf.PermanentError("Some required variable is not set: KEYCLOAK_CLIENT, KEYCLOAK_CLIENT_SECRET, DATASET_SERVICE_ENDPOINT, KEYCLOAK_ENDPOINT, KEYCLOAK_REALM, OPERATOR_SERVICE_ACCOUNT_NAME, OPERATOR_SERVICE_ACCOUNT_NAMESPACE")
    
    if not KEYCLOAK_MAX_RETRIES:
        KEYCLOAK_MAX_RETRIES = DEFAULT_KEYCLOAK_MAX_RETRIES
    else:
        KEYCLOAK_MAX_RETRIES = int(KEYCLOAK_MAX_RETRIES)

    if not DATASET_SERVICE_MAX_RETRIES:
        DATASET_SERVICE_MAX_RETRIES = DEFAULT_DATASET_SERVICE_MAX_RETRIES
    else:
        DATASET_SERVICE_MAX_RETRIES = int(DATASET_SERVICE_MAX_RETRIES)
    
    # Remove (if exists) the "/" from endpoints
    if KEYCLOAK_ENDPOINT[-1] == "/":
        KEYCLOAK_ENDPOINT = KEYCLOAK_ENDPOINT[:-1]
    if DATASET_SERVICE_ENDPOINT[-1] == "/":
        DATASET_SERVICE_ENDPOINT = DATASET_SERVICE_ENDPOINT[:-1]  
    
    logger.info( "Chaimeleon operator (v{version}) options: KEYCLOAK_CLIENT={keycloak_client}, KEYCLOAK_ENDPOINT={keycloak_endpoint}, KEYCLOAK_REALM={realm}, DATASET_SERVICE_ENDPOINT={dataset_endpoint}, K8S_USER_PREFIX='{user_prefix}'".format(version=__VERSION__, keycloak_client=KEYCLOAK_CLIENT, keycloak_endpoint=KEYCLOAK_ENDPOINT, realm=KEYCLOAK_REALM, dataset_endpoint=DATASET_SERVICE_ENDPOINT, user_prefix=K8S_USER_PREFIX ) )

@kopf.on.create('apps/v1', 'deployments', annotations={'chaimeleon.eu/datasetsIDs': kopf.PRESENT, 'chaimeleon.eu/toolName': kopf.PRESENT, 'chaimeleon.eu/toolVersion': kopf.PRESENT})
@kopf.on.create('batch/v1', 'jobs', annotations={'chaimeleon.eu/datasetsIDs': kopf.PRESENT, 'chaimeleon.eu/toolName': kopf.PRESENT, 'chaimeleon.eu/toolVersion': kopf.PRESENT})
def create_fn(spec, name, namespace, logger, body, uid, **kwargs):
    global LOCK, LOCAL_STORAGE, KEYCLOAK_CLIENT, K8S_USER_PREFIX

    MY_VALIDATION_INFO = None
    LOCK.acquire(blocking=True)
    if uid in LOCAL_STORAGE:
        MY_VALIDATION_INFO = LOCAL_STORAGE[uid]
    else:
        logger.error("Someone is deploying an app with uid=%s that was not correctly validated, we are not able to trace this dataset access" % (uid) )
    LOCK.release()
    
    if MY_VALIDATION_INFO != None:
        access_token = get_access_token(logger)
        username = dict(MY_VALIDATION_INFO["userinfo"])["username"]
        keycloak_username = username[ len(K8S_USER_PREFIX): ]
        if access_dataset(logger, access_token, uid, keycloak_username, MY_VALIDATION_INFO["datasetsID"], MY_VALIDATION_INFO["toolName"], MY_VALIDATION_INFO["toolVersion"]):
            logger.info( "uid={uid} -> Access dataset successfully traced: User={username}, tool={toolName}:{toolVersion} , datasets:{datasets}".format(uid=uid, username=keycloak_username, toolName=MY_VALIDATION_INFO["toolName"], toolVersion=MY_VALIDATION_INFO["toolVersion"], datasets=str(MY_VALIDATION_INFO["datasetsID"])) )
        else:
            logger.error( "uid={uid} -> Access dataset unsuccessfully traced: User={username}, tool={toolName}:{toolVersion} , datasets:{datasets}".format(uid=uid, username=keycloak_username, toolName=MY_VALIDATION_INFO["toolName"], toolVersion=MY_VALIDATION_INFO["toolVersion"], datasets=str(MY_VALIDATION_INFO["datasetsID"])) )

@kopf.on.delete('apps/v1', 'deployments', annotations={'chaimeleon.eu/datasetsIDs': kopf.PRESENT, 'chaimeleon.eu/toolName': kopf.PRESENT, 'chaimeleon.eu/toolVersion': kopf.PRESENT})
@kopf.on.delete('batch/v1', 'jobs', annotations={'chaimeleon.eu/datasetsIDs': kopf.PRESENT, 'chaimeleon.eu/toolName': kopf.PRESENT, 'chaimeleon.eu/toolVersion': kopf.PRESENT})
def remove_fn(spec, name, namespace, logger, body, uid, **kwargs):
    global LOCK, LOCAL_STORAGE, KEYCLOAK_CLIENT

    MY_VALIDATION_INFO = None
    LOCK.acquire(blocking=True)
    if uid in LOCAL_STORAGE:
        MY_VALIDATION_INFO = LOCAL_STORAGE[uid]
    else:
        logger.error("Someone is deleting an app with uid=%s that was not correctly validated, we are not able to trace this dataset access" % (uid) )
    LOCK.release()
    
    if MY_VALIDATION_INFO != None:
        username = dict(MY_VALIDATION_INFO["userinfo"])["username"]
        access_token = get_access_token(logger)    
        if finalise_access_dataset(logger, access_token, uid):
            logger.info( "uid={uid} -> Finalise accessing dataset successfully traced: User={username}, tool={toolName}:{toolVersion} , datasets:{datasets}".format(username=username, toolName=MY_VALIDATION_INFO["toolName"], toolVersion=MY_VALIDATION_INFO["toolVersion"], datasets=str(MY_VALIDATION_INFO["datasetsID"])) )
        else:
            logger.error( "uid={uid} -> Finalise accessing dataset unsuccessfully traced: User={username}, tool={toolName}:{toolVersion} , datasets:{datasets}".format(uid=uid, username=username, toolName=MY_VALIDATION_INFO["toolName"], toolVersion=MY_VALIDATION_INFO["toolVersion"], datasets=str(MY_VALIDATION_INFO["datasetsID"])) )

@kopf.on.validate('apps/v1', 'deployments', annotations={'chaimeleon.eu/datasetsIDs': kopf.PRESENT, 'chaimeleon.eu/toolName': kopf.PRESENT, 'chaimeleon.eu/toolVersion': kopf.PRESENT}, operation='CREATE')
def validate_create_deployment_fn(spec, logger, userinfo, body, warnings, headers, uid, annotations, **kwargs):
    global OPERATOR_SERVICE_ACCOUNT_NAME, OPERATOR_SERVICE_ACCOUNT_NAMESPACE
    if (userinfo['username'] != "system:serviceaccount:{namespace}:{service_account}".format(namespace=OPERATOR_SERVICE_ACCOUNT_NAMESPACE, service_account=OPERATOR_SERVICE_ACCOUNT_NAME)):
        validate(spec, logger, userinfo, body, warnings, headers, uid, annotations)

@kopf.on.validate('batch/v1', 'jobs', annotations={'chaimeleon.eu/datasetsIDs': kopf.PRESENT, 'chaimeleon.eu/toolName': kopf.PRESENT, 'chaimeleon.eu/toolVersion': kopf.PRESENT}, operation='CREATE')
def validate_create_job_fn(spec, logger, userinfo, body, warnings, headers, uid, annotations, **kwargs):
    global OPERATOR_SERVICE_ACCOUNT_NAME, OPERATOR_SERVICE_ACCOUNT_NAMESPACE
    if (userinfo['username'] != "system:serviceaccount:{namespace}:{service_account}".format(namespace=OPERATOR_SERVICE_ACCOUNT_NAMESPACE, service_account=OPERATOR_SERVICE_ACCOUNT_NAME)) :
        validate(spec, logger, userinfo, body, warnings, headers, uid, annotations)

@kopf.on.validate('apps/v1', 'deployments', annotations={'chaimeleon.eu/datasetsIDs': kopf.PRESENT, 'chaimeleon.eu/toolName': kopf.PRESENT, 'chaimeleon.eu/toolVersion': kopf.PRESENT}, operation='UPDATE')
def validate_update_deployment_fn(spec, logger, userinfo, body, warnings, headers, uid, annotations, **kwargs):
    global OPERATOR_SERVICE_ACCOUNT_NAME, OPERATOR_SERVICE_ACCOUNT_NAMESPACE
    if (userinfo['username'] != "system:serviceaccount:{namespace}:{service_account}".format(namespace=OPERATOR_SERVICE_ACCOUNT_NAMESPACE, service_account=OPERATOR_SERVICE_ACCOUNT_NAME)):
        validate(spec, logger, userinfo, body, warnings, headers, uid, annotations)

@kopf.on.validate('batch/v1', 'jobs', annotations={'chaimeleon.eu/datasetsIDs': kopf.PRESENT, 'chaimeleon.eu/toolName': kopf.PRESENT, 'chaimeleon.eu/toolVersion': kopf.PRESENT}, operation='UPDATE')
def validate_update_job_fn(spec, logger, userinfo, body, warnings, headers, uid, annotations, **kwargs):
    global OPERATOR_SERVICE_ACCOUNT_NAME, OPERATOR_SERVICE_ACCOUNT_NAMESPACE
    if (userinfo['username'] != "system:serviceaccount:{namespace}:{service_account}".format(namespace=OPERATOR_SERVICE_ACCOUNT_NAMESPACE, service_account=OPERATOR_SERVICE_ACCOUNT_NAME)) :
        validate(spec, logger, userinfo, body, warnings, headers, uid, annotations)

def validate(spec, logger, userinfo, body, warnings, headers, uid, annotations):
    global LOCK, LOCAL_STORAGE, K8S_USER_PREFIX, OPERATOR_SERVICE_ACCOUNT_NAME, OPERATOR_SERVICE_ACCOUNT_NAMESPACE
    
    # Avoid validate the modifications performed by the Chaimeleon operator in mutation weebhooks
    if (userinfo['username'] != "system:serviceaccount:{namespace}:{service_account}".format(namespace=OPERATOR_SERVICE_ACCOUNT_NAMESPACE, service_account=OPERATOR_SERVICE_ACCOUNT_NAME)):
        gid=None
        _spec = dict(spec)
        
        if "securityContext" not in _spec["template"]["spec"]:
            raise kopf.AdmissionError("Missing spec.securityContext in the Deployment.")

        if not "supplementalGroups" in _spec["template"]["spec"]["securityContext"]:
            raise kopf.AdmissionError("Missing spec.securityContext.supplementalGroups.")

        if not isinstance(_spec["template"]["spec"]["securityContext"]["supplementalGroups"], list) or len(_spec["template"]["spec"]["securityContext"]["supplementalGroups"]) != 1:
            raise kopf.AdmissionError("The property spec.securityContext.supplementalGroups must be a list with one element.")

        gid = _spec["template"]["spec"]["securityContext"]["supplementalGroups"][0]
        datasets = annotations["chaimeleon.eu/datasetsIDs"].replace(" ", "").split(",")
        toolName = annotations["chaimeleon.eu/toolName"].replace(" ", "")
        toolVersion = annotations["chaimeleon.eu/toolVersion"].replace(" ", "")

        # Remove Kubernetes prefix for username
        keycloak_username = userinfo['username'][ len(K8S_USER_PREFIX): ]

        if not isinstance(datasets, list):
            raise kopf.AdmissionError("The annotation 'chaimeleon.eu/datasetsIDs' must be a list of datasetsIDs sepparated with ','")

        logger.debug( "Starting validation uid=%s -> username=%s, toolName=%s, toolVersion=%s, providedGID=%s, datasets=%s" % (uid, keycloak_username, toolName, toolVersion, str(gid), str(datasets)) )

        validation_ok = False

        if len(datasets) == 0:
            logger.info( "uid=%s -> User %s will deploy toolName=%s without datasets" % (uid, keycloak_username, toolName) )
            validation_ok = True
        else:
            access_token = get_access_token(logger)

            if access_token:
                # Check if the GID provided by the user is correct    
                if not check_gid_user(logger, access_token, keycloak_username, gid):
                    logger.warning( "uid=%s -> User %s is trying to use another GID than the GID obtained from Dataset Service" % (uid, keycloak_username) )
                    raise kopf.AdmissionError( "Access denied because you are using an unauthorized supplementalGroup for you. Please contact CHAIMELEON adminisstrators to solve it.")

                access_checked = check_access_dataset(logger, access_token, keycloak_username, datasets)
                
                # Check with Dataset Service if the user can use the datasets requested
                if len(access_checked["denied"])>0:
                    logger.warning( "uid=%s -> User %s is trying to use dataset(s) that is not allowed: %s" % (uid, keycloak_username, str(access_checked["denied"]) ) )
                    raise kopf.AdmissionError( "Access denied to the following datasets: %s" % (str(access_checked["denied"])) )

                logger.debug("Validation uid=%s ended successfully" % (uid))
                validation_ok = True
            else:
                logger.error( "uid=%s -> Cannot obtain access token for client %s in Keycloak" % (uid, KEYCLOAK_CLIENT) )
                raise kopf.AdmissionError( "Cannot validate the deployment, please contact the administrators" )

        if validation_ok:
            # Store userinfo
            LOCK.acquire(blocking=True)
            LOCAL_STORAGE[ uid ] = { "userinfo": userinfo, "datasetsID": datasets, "toolName": toolName, "toolVersion": toolVersion }
            LOCK.release()

def get_access_token(logger):
    global KEYCLOAK_CLIENT, KEYCLOAK_CLIENT_SECRET, KEYCLOAK_ENDPOINT, KEYCLOAK_REALM, KEYCLOAK_MAX_RETRIES

    access_token = None

    URL = "{endpoint}/auth/realms/{realm}/protocol/openid-connect/token".format(endpoint=KEYCLOAK_ENDPOINT, realm=KEYCLOAK_REALM) 
    data = { "client_id": KEYCLOAK_CLIENT, "client_secret": KEYCLOAK_CLIENT_SECRET, "grant_type": "client_credentials"}
    
    response = do_request_post(URL, "POST", logger, KEYCLOAK_MAX_RETRIES, data=data, verify=True)

    if response.status_code == 200:
       access_token = response.json()['access_token']
   
    if not access_token:
        logger.error("Cannot obtain the access_token. Response: status_code=%d, text=%s" % (response.status_code, response.text))

    return access_token

def check_access_dataset(logger, access_token, username, datasets_list):
    global DATASET_SERVICE_ENDPOINT, DATASET_SERVICE_MAX_RETRIES

    result = { 'granted': [], 'denied': [] }
    URL = "{endpoint}/api/datasetAccessCheck".format(endpoint=DATASET_SERVICE_ENDPOINT) 
    data = { "userName": username, "datasets": datasets_list }
    headers= { "Content-Type": "application/json", "Accept": "application/json", "Authorization": "bearer %s" % (access_token)  }

    response =  do_request_post(URL, "POST", logger, DATASET_SERVICE_MAX_RETRIES, headers=headers, data=json.dumps(data), verify=False)

    if response.status_code == 204:
        result['granted'] = datasets_list 
    elif response.status_code == 403:
        result['denied'] = response.json()
        for datasetID in datasets_list:
            if datasetID not in result['denied']:
                 result['granted'].append(datasetID)
    else:
         result['denied'] = datasets_list 
         
         if response.status_code == 401:
             logger.error("Invalid access token used at --check_access_dataset-- function: %s" % (response.text))
         else:
             logger.error("Error at --check_access_dataset-- function: %s" % (response.text))

    return result

def check_gid_user(logger, access_token, username, gid):
    global DATASET_SERVICE_ENDPOINT, DATASET_SERVICE_MAX_RETRIES

    URL = "{endpoint}/api/user/{username}".format(endpoint=DATASET_SERVICE_ENDPOINT, username=username) 
    headers= { "Content-Type": "application/json", "Accept": "application/json", "Authorization": "bearer %s" % (access_token)  }

    response =  do_request_post(URL, "GET" , logger, DATASET_SERVICE_MAX_RETRIES, headers=headers, verify=False)

    gid_obtained = None
    if response.status_code == 200:
        gid_obtained = int(response.json()['gid'])
    elif response.status_code == 404:
        logger.error("User %s not found in Dataset Service: %s" % (username, response.text))
    else:
        logger.error("Error at --check_gid_user-- function: %s" % (response.text))

    return int(gid) == gid_obtained

def access_dataset(logger, access_token, id, username, datasets_list, toolName, toolVersion):
    global DATASET_SERVICE_ENDPOINT, DATASET_SERVICE_MAX_RETRIES

    result = False
    URL = "{endpoint}/api/datasetAccess/{id}".format(endpoint=DATASET_SERVICE_ENDPOINT,id=id) 
    data = { "userName": username, "datasets": datasets_list, "toolName": toolName, "toolVersion": toolVersion }
    headers= { "Content-Type": "application/json", "Accept": "application/json", "Authorization": "bearer %s" % (access_token)  }

    logger.debug( "uid={id} -> User {username} with {toolName}:{toolVersion} is using the following datasets: {datasets}".format(id=id, username=username, toolName=toolName, toolVersion=toolVersion, datasets=str(datasets_list)) )

    response =  do_request_post(URL, "POST", logger, DATASET_SERVICE_MAX_RETRIES, headers=headers, data=json.dumps(data), verify=False)

    if response.status_code == 201:
        result = True
    else:
         if response.status_code == 401:
            logger.error("Invalid access token used at --access_dataset-- function: %s" % (response.text))
         

    return result

def finalise_access_dataset(logger, access_token, id):
    global DATASET_SERVICE_ENDPOINT, DATASET_SERVICE_MAX_RETRIES

    result = False
    URL = "{endpoint}/api/datasetAccess/{id}".format(endpoint=DATASET_SERVICE_ENDPOINT,id=id) 
    headers= { "Content-Type": "application/json", "Accept": "application/json", "Authorization": "bearer %s" % (access_token)  }

    response =  do_request_post(URL, "DELETE", logger, DATASET_SERVICE_MAX_RETRIES, headers=headers, verify=False)

    if response.status_code == 200:
        logger.debug( "uid={id} -> Deletion of dataset access successfully performed at Dataset service}".format(id=id) )
        result = True
    elif response.status_code == 401:
        logger.error("Invalid access token used at --finalise_access_dataset-- function: %s" % (response.text))
    else:
        logger.error("Error at --finalise_access_dataset-- function: %s" % (response.text))

    return result

def do_request_post(URL, method, logger, max_retries, data=None, headers=None, verify=True):
    r = None
    ok = False
    current_retries = 0
    while ( current_retries < max_retries) and (not ok) :
            current_retries += 1
            try: 
                r =  requests.request(method, URL, data=data, verify=verify, headers=headers)
                ok = True
            except requests.exceptions.ConnectionError:
                logger.warning("Cannot connect to %s, waiting %d seconds..." % (URL, 1))
                time.sleep(1)
            except:
                logger.warning("Cannot process the response (status_code =%d). Message: %s" % (r.status_code, r.text))
    
    if not ok:
        logger.error("Cannot connect to %s (retries = %d)" % (URL, max_retries))
    return r