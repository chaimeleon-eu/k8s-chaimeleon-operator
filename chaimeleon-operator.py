import kopf
import kubernetes
import base64
import os 
import json
import requests
import time
import guacli.guacamoleClient as guac
import http.client
import urllib.parse
from datetime import datetime

__VERSION__ = "2.1.0"

OPERATOR_SERVICE_ACCOUNT_NAME = None
OPERATOR_SERVICE_ACCOUNT_NAMESPACE = None
KEYCLOAK_CLIENT = None
KEYCLOAK_CLIENT_SECRET = None
KEYCLOAK_ENDPOINT= None
KEYCLOAK_REALM = None
DATASET_SERVICE_ENDPOINT = None
DATASET_SERVICE_TEST_ENDPOINT = None

KEYCLOAK_MAX_RETRIES = None
DATASET_SERVICE_MAX_RETRIES = None
DEFAULT_KEYCLOAK_MAX_RETRIES = 10
DEFAULT_DATASET_SERVICE_MAX_RETRIES = 10

K8S_USER_PREFIX=""
SYSTEM_SERVICE_ACCOUNTS = []

GUACAMOLE_URL = None
GUACAMOLE_USER = None
GUACAMOLE_PASSWORD = None
GUACAMOLE_CONNECTIONS_BACKEND_HOST = 'guacamole-guacd.guacamole.svc.cluster.local'
GUACAMOLE_CONNECTIONS_VNC_PORT = '5900'
GUACAMOLE_CONNECTIONS_SFTP_USERNAME = 'chaimeleon'
GUACAMOLE_CONNECTIONS_SFTP_PORT = '2222'

@kopf.on.login(retries=3)
def login_fn(**kwargs):
    # Login using the service account that is mounted automatically in the container
    return kopf.login_via_pykube(**kwargs)

@kopf.on.startup()
def config(settings: kopf.OperatorSettings, logger, **_):
    global KEYCLOAK_CLIENT, KEYCLOAK_CLIENT_SECRET, KEYCLOAK_ENDPOINT, KEYCLOAK_REALM, DATASET_SERVICE_ENDPOINT, DATASET_SERVICE_TEST_ENDPOINT
    global DEFAULT_KEYCLOAK_MAX_RETRIES, KEYCLOAK_MAX_RETRIES, DEFAULT_DATASET_SERVICE_MAX_RETRIES, DATASET_SERVICE_MAX_RETRIES
    global K8S_USER_PREFIX, OPERATOR_SERVICE_ACCOUNT_NAMESPACE, OPERATOR_SERVICE_ACCOUNT_NAME, SYSTEM_SERVICE_ACCOUNTS
    global GUACAMOLE_URL, GUACAMOLE_USER, GUACAMOLE_PASSWORD, GUACAMOLE_CONNECTIONS_BACKEND_HOST
    global GUACAMOLE_CONNECTIONS_VNC_PORT, GUACAMOLE_CONNECTIONS_SFTP_USERNAME, GUACAMOLE_CONNECTIONS_SFTP_PORT

    # Required ENV vars
    KEYCLOAK_CLIENT = os.getenv('KEYCLOAK_CLIENT')
    KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET')
    KEYCLOAK_ENDPOINT = os.getenv('KEYCLOAK_ENDPOINT')
    KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM')
    DATASET_SERVICE_ENDPOINT = os.getenv('DATASET_SERVICE_ENDPOINT')
    OPERATOR_SERVICE_ACCOUNT_NAMESPACE = os.getenv('OPERATOR_SERVICE_ACCOUNT_NAMESPACE')
    OPERATOR_SERVICE_ACCOUNT_NAME = os.getenv('OPERATOR_SERVICE_ACCOUNT_NAME')

    OPERATOR_SERVICE_HOST = str(os.getenv('CHAIMELEON_OPERATOR_SERVICE_HOST'))
    OPERATOR_SERVICE_PORT = str(os.getenv('CHAIMELEON_OPERATOR_SERVICE_PORT'))

    # Optional ENV vars
    KEYCLOAK_MAX_RETRIES = os.getenv('KEYCLOAK_MAX_RETRIES')
    DATASET_SERVICE_MAX_RETRIES = os.getenv('DATASET_SERVICE_MAX_RETRIES')
    K8S_USER_PREFIX = str(os.getenv('K8S_USER_PREFIX'))
    DATASET_SERVICE_TEST_ENDPOINT = os.getenv('DATASET_SERVICE_TEST_ENDPOINT')
    if DATASET_SERVICE_TEST_ENDPOINT == "": DATASET_SERVICE_TEST_ENDPOINT = None

    GUACAMOLE_URL = os.environ.get('GUACAMOLE_URL', GUACAMOLE_URL)
    GUACAMOLE_USER = os.environ.get('GUACAMOLE_USER', GUACAMOLE_USER)
    GUACAMOLE_PASSWORD = os.environ.get('GUACAMOLE_PASSWORD', GUACAMOLE_PASSWORD)
    GUACAMOLE_CONNECTIONS_BACKEND_HOST = os.environ.get('GUACAMOLE_CONNECTIONS_BACKEND_HOST', GUACAMOLE_CONNECTIONS_BACKEND_HOST)
    GUACAMOLE_CONNECTIONS_VNC_PORT = os.environ.get('GUACAMOLE_CONNECTIONS_VNC_PORT', GUACAMOLE_CONNECTIONS_VNC_PORT)
    GUACAMOLE_CONNECTIONS_SFTP_USERNAME = os.getenv('GUACAMOLE_CONNECTIONS_SFTP_USERNAME', GUACAMOLE_CONNECTIONS_SFTP_USERNAME)
    GUACAMOLE_CONNECTIONS_SFTP_PORT = os.getenv('GUACAMOLE_CONNECTIONS_SFTP_PORT', GUACAMOLE_CONNECTIONS_SFTP_PORT)

    #logger.info("OPERATOR_SERVICE_HOST=%s" % (OPERATOR_SERVICE_HOST))
    #logger.info("OPERATOR_SERVICE_PORT=%s" % (OPERATOR_SERVICE_PORT))
    if not OPERATOR_SERVICE_PORT or not OPERATOR_SERVICE_HOST:
        raise kopf.PermanentError("You must deploy a service ClusterIP to expose the operator with the name 'chaimeleon-operator' "
                                  "(this operator gets the env variables CHAIMELEON_OPERATOR_SERVICE_HOST and CHAIMELEON_OPERATOR_SERVICE_PORT)")

    settings.admission.server = kopf.WebhookServer(host=OPERATOR_SERVICE_HOST, port=int(OPERATOR_SERVICE_PORT))
    settings.admission.managed = 'chaimeleon.eu'

    # Fix: https://github.com/nolar/kopf/issues/585
    settings.watching.client_timeout = 600
    settings.watching.server_timeout = 600
    settings.watching.connect_timeout = 60

    if not KEYCLOAK_CLIENT or not KEYCLOAK_CLIENT_SECRET or not KEYCLOAK_ENDPOINT or not KEYCLOAK_REALM \
        or not DATASET_SERVICE_ENDPOINT or not OPERATOR_SERVICE_ACCOUNT_NAME or not OPERATOR_SERVICE_ACCOUNT_NAMESPACE:
        raise kopf.PermanentError("Some required variable is not set: KEYCLOAK_CLIENT, KEYCLOAK_CLIENT_SECRET, KEYCLOAK_ENDPOINT, KEYCLOAK_REALM, "
                                  "DATASET_SERVICE_ENDPOINT, OPERATOR_SERVICE_ACCOUNT_NAME, OPERATOR_SERVICE_ACCOUNT_NAMESPACE")
        
    KEYCLOAK_MAX_RETRIES = DEFAULT_KEYCLOAK_MAX_RETRIES if not KEYCLOAK_MAX_RETRIES else int(KEYCLOAK_MAX_RETRIES)
    DATASET_SERVICE_MAX_RETRIES = DEFAULT_DATASET_SERVICE_MAX_RETRIES if not DATASET_SERVICE_MAX_RETRIES else int(DATASET_SERVICE_MAX_RETRIES)
    
    # Remove (if exists) the "/" from endpoints
    if KEYCLOAK_ENDPOINT[-1] == "/":
        KEYCLOAK_ENDPOINT = KEYCLOAK_ENDPOINT[:-1]
    if DATASET_SERVICE_ENDPOINT[-1] == "/":
        DATASET_SERVICE_ENDPOINT = DATASET_SERVICE_ENDPOINT[:-1]  
    if DATASET_SERVICE_TEST_ENDPOINT != None and DATASET_SERVICE_TEST_ENDPOINT[-1] == "/":
        DATASET_SERVICE_TEST_ENDPOINT = DATASET_SERVICE_TEST_ENDPOINT[:-1]  
    
    logger.info( "Chaimeleon operator (v{}) options: KEYCLOAK_CLIENT={}, KEYCLOAK_ENDPOINT={}, KEYCLOAK_REALM={}, "
                 "DATASET_SERVICE_ENDPOINT={}, DATASET_SERVICE_TEST_ENDPOINT={}, K8S_USER_PREFIX='{}'"
                 .format(__VERSION__, KEYCLOAK_CLIENT, KEYCLOAK_ENDPOINT, KEYCLOAK_REALM, 
                         DATASET_SERVICE_ENDPOINT, DATASET_SERVICE_TEST_ENDPOINT, K8S_USER_PREFIX ) )

    # There are some special users that we must let them mutate resources without validate: they are trusted users and their changes are secure.
    SYSTEM_SERVICE_ACCOUNTS = []
    # This operator
    SYSTEM_SERVICE_ACCOUNTS.append(f"system:serviceaccount:{OPERATOR_SERVICE_ACCOUNT_NAMESPACE}:{OPERATOR_SERVICE_ACCOUNT_NAME}")
    # The garbage collector sometimes mutates a deployment before delete
    SYSTEM_SERVICE_ACCOUNTS.append("system:serviceaccount:kube-system:generic-garbage-collector")

ANNOTATION_DATASETS_IDS = "chaimeleon.eu/datasetsIDs"
ANNOTATION_TOOL_NAME = "chaimeleon.eu/toolName"
ANNOTATION_TOOL_VERSION = "chaimeleon.eu/toolVersion"
ANNOTATION_USERNAME = "chaimeleon.eu/username"
ANNOTATION_CREATE_GUACAMOLE_CONNECTION = "chaimeleon.eu/createGuacamoleConnection"
ANNOTATION_GUACAMOLE_CONNECTION_NAME = "chaimeleon.eu/guacamoleConnectionName"
ANNOTATION_JOB_RESOURCES_FLAVOR = "chaimeleon.eu/jobResourcesFlavor"
ANNOTATION_TESTING_ENVIRONMENT = "chaimeleon.eu/testingEnvironment"

DATASET_ACCESS_ANNOTATIONS = {ANNOTATION_DATASETS_IDS: kopf.PRESENT, ANNOTATION_TOOL_NAME: kopf.PRESENT, ANNOTATION_TOOL_VERSION: kopf.PRESENT}

# The 'id' is required when multiple decorators on the same function.
# The 'param' is useful for identifying which decorator has been triggered.

@kopf.on.mutate('apps/v1', 'deployments', id='mutate_deployment_fn', param='deployment', annotations=DATASET_ACCESS_ANNOTATIONS)
@kopf.on.mutate('batch/v1', 'jobs', id='mutate_job_fn', param='job', annotations=DATASET_ACCESS_ANNOTATIONS)
def mutate_deployment_or_job_fn(param, spec, patch, logger, userinfo, uid, name, namespace, annotations, **_):
    # Skip the modifications performed by system service accounts
    if userinfo['username'] in SYSTEM_SERVICE_ACCOUNTS: return
    # We only have to manage deployments and jobs from normal users, and they only have permissions to deploy in their own namespaces
    if not str(namespace).startswith("user-"): return
    username = namespace[5:]
    #username = userinfo['username'][ len(K8S_USER_PREFIX): ]    # Remove Kubernetes prefix for username
    # userinfo is the k8s user, which can be an admin deploying or adjusting a deployment for the user
    
    logger.debug("############# EVENT for prepare "+param)
    prepare_deployment_or_job_for_dataset_access(name, annotations, spec, patch, logger, username)
    logger.debug(f"Mutation ended successfully")


# @kopf.on.validate('apps/v1', 'deployments', id='validate_create_deployment_fn', annotations=DATASET_ACCESS_ANNOTATIONS, operation='CREATE')
# @kopf.on.validate('batch/v1', 'jobs', id='validate_create_job_fn', annotations=DATASET_ACCESS_ANNOTATIONS, operation='CREATE')
# @kopf.on.validate('apps/v1', 'deployments', id='validate_update_deployment_fn', annotations=DATASET_ACCESS_ANNOTATIONS, operation='UPDATE')
# @kopf.on.validate('batch/v1', 'jobs', id='validate_update_job_fn', annotations=DATASET_ACCESS_ANNOTATIONS, operation='UPDATE')
# def validate_deployment_or_job_fn(spec, logger, userinfo, body, warnings, headers, uid, annotations, **kwargs):
#     # Skip the modifications performed by system service accounts
#     if userinfo['username'] in SYSTEM_SERVICE_ACCOUNTS: return
#
#     validate_dataset_access(spec, logger, userinfo, body, warnings, headers, uid, annotations)

@kopf.on.create('apps/v1', 'deployments', id='create_deployment_fn', param='deployment', annotations=DATASET_ACCESS_ANNOTATIONS)
@kopf.on.create('batch/v1', 'jobs', id='create_job_fn', param='job', annotations=DATASET_ACCESS_ANNOTATIONS)
def create_deployment_or_job_fn(param, spec, name, namespace, logger, body, uid, annotations, **kwargs):
    logger.debug("############# EVENT for notify the start of dataset access by a "+ param)
    # logger.debug("############# BODY: "+ json.dumps(dict(body)))
    #if bool(annotations[ANNOTATION_TESTING_ENVIRONMENT]):
    if ANNOTATION_CREATE_GUACAMOLE_CONNECTION in annotations and str(annotations[ANNOTATION_CREATE_GUACAMOLE_CONNECTION]).strip().lower() == 'true':
        create_guacamole_connection(name, namespace, spec, annotations, logger)
    notify_dataset_access(spec, name, namespace, logger, body, uid, annotations)

# @kopf.on.update('apps/v1', 'deployments', annotations=DATASET_ACCESS_ANNOTATIONS)
# def my_handler(spec, old, new, diff, **_):
#     pass

@kopf.on.delete('apps/v1', 'deployments', id='delete_deployment_fn', param='deployment', annotations=DATASET_ACCESS_ANNOTATIONS)
@kopf.on.delete('batch/v1', 'jobs', id='delete_job_fn', param='job', annotations=DATASET_ACCESS_ANNOTATIONS)
def delete_deployment_or_job_fn(param, spec, name, namespace, logger, body, uid, annotations, **kwargs):
    logger.debug("############# EVENT for notify the end of dataset access by a " + param)
    notify_end_of_dataset_access(spec, name, namespace, logger, body, uid, annotations)
    if ANNOTATION_CREATE_GUACAMOLE_CONNECTION in annotations and str(annotations[ANNOTATION_CREATE_GUACAMOLE_CONNECTION]).strip().lower() == 'true':
        delete_guacamole_connection(name, annotations, logger)

# @kopf.on.create('v1', 'services', annotations={ANNOTATION_CREATE_GUACAMOLE_CONNECTION: kopf.PRESENT})
# def create_service_fn(spec, name, namespace, logger, body, uid, annotations, **kwargs):
#     create_guacamole_connection(name, namespace, spec, annotations, logger)

# @kopf.on.delete('v1', 'services', annotations={ANNOTATION_CREATE_GUACAMOLE_CONNECTION: kopf.PRESENT})
# def delete_service_fn(spec, name, namespace, logger, body, uid, annotations, **kwargs):
#     #delete_guacamole_connection()

# @kopf.on.event('apps/v1', 'deployments')
# def my_handler(event, logger, **_):
#     logger.debug("############# SOME DEPLOYMENT event.")


def get_guacamole_client(url):
    urlp = urllib.parse.urlparse(url)
    if urlp.hostname is None: raise Exception('Wrong url.')
    port = urlp.port
    if urlp.scheme == 'http':
        if port == None: port = 80
        connection = http.client.HTTPConnection(urlp.hostname, port) 
    else:
        if port == None: port = 443
        connection = http.client.HTTPSConnection(urlp.hostname, port)
    return guac.GuacamoleClient(connection, urlp.path)

def get_container_password_from_secret(secret_name, namespace):
    #kubernetes.config.load_kube_config()
    kubernetes.config.load_incluster_config()
    api = kubernetes.client.CoreV1Api()
    secret = api.read_namespaced_secret(secret_name, namespace)
    password = secret.data["container-password"]
    decoded = base64.b64decode(password).decode('utf-8')
    return decoded

def create_guacamole_connection(name, namespace, spec, annotations, logger):
    if GUACAMOLE_URL is None: return   # Guacamole connection creation is disabled
    client = get_guacamole_client(GUACAMOLE_URL)
    logger.debug('Connecting to '+GUACAMOLE_URL+ 'api/')
    client.login(GUACAMOLE_USER, GUACAMOLE_PASSWORD)
    logger.debug('Login success.')

    username = annotations[ANNOTATION_USERNAME]
    connectionGroupId = client.getConnectionGroupId(username)
    if connectionGroupId is None: logger.warning('Connection group "'+username+'" not found.'); return

    connectionName = annotations[ANNOTATION_GUACAMOLE_CONNECTION_NAME]
    vnc_host = f"{name}.{namespace}.svc.cluster.local"   # A k8s service with the same name should be created in the same namespace
    vnc_port = GUACAMOLE_CONNECTIONS_VNC_PORT
    vnc_password = get_container_password_from_secret(name, namespace)
    logger.debug("############# SECRET content: "+ vnc_password)
    sftp_port = GUACAMOLE_CONNECTIONS_SFTP_PORT
    sftp_user = GUACAMOLE_CONNECTIONS_SFTP_USERNAME
    sftp_password = vnc_password
    logger.debug('Creating VNC connection for '+vnc_host+':'+vnc_port)
    connectionId = client.createVncConnection(connectionName, connectionGroupId, GUACAMOLE_CONNECTIONS_BACKEND_HOST, 
                                            vnc_host, vnc_port, vnc_password, sftp_user, sftp_password, sftp_port, 
                                            sftp_disable_download=True, sftp_disable_upload=False,
                                            disable_clipboard_copy=True, disable_clipboard_paste=False)
    client.changeUserAccessToConnection(username, guac.PermissionsOperation.ADD, connectionId)

def delete_guacamole_connection(name, annotations, logger):
    if GUACAMOLE_URL is None: return   # Guacamole connection creation is disabled
    client = get_guacamole_client(GUACAMOLE_URL)
    logger.debug('Connecting to '+GUACAMOLE_URL+ 'api/')
    client.login(GUACAMOLE_USER, GUACAMOLE_PASSWORD)
    logger.debug('Login success.')

    username = annotations[ANNOTATION_USERNAME]
    connectionGroupId = client.getConnectionGroupId(username)
    if connectionGroupId is None: logger.warning('Connection group "'+username+'" not found.'); return

    connectionName = annotations[ANNOTATION_GUACAMOLE_CONNECTION_NAME]
    connectionId = client.getConnectionId(connectionName, connectionGroupId)
    if connectionId is None: logger.warning(f'Guacamole connection {connectionName} not found in the {username} connections group'); return
    
    logger.debug(f'Deleting guacamole connection {connectionId}: {connectionName}')
    client.deleteConnection(connectionId)

def prepare_deployment_or_job_for_dataset_access(name, annotations, spec, patch, logger, username):
    logger.debug("############# prev securityContext (SPEC): " + json.dumps(spec['template']['spec']['securityContext']))
    securityContext = {'runAsUser': 1000, 'runAsGroup': 1000, 'fsGroup': 1000}
    logger.debug("############# Adding securityContext: " + json.dumps(dict(securityContext)))
    patch.spec['template'] = {'spec': {'securityContext': securityContext}}

    datasets = annotations[ANNOTATION_DATASETS_IDS].replace(" ", "").split(",")
    toolName = annotations[ANNOTATION_TOOL_NAME].replace(" ", "")
    if not isinstance(datasets, list):
        raise kopf.AdmissionError(f"The annotation '{ANNOTATION_DATASETS_IDS}' must be a list of datasetsIDs sepparated with ','")
    testingEnvironment = False
    if len(datasets) == 0:
        logger.info(f"User {username} will deploy toolName={toolName} without datasets")
    else:
        access_token = get_access_token(logger)
        if not access_token:
            raise kopf.AdmissionError("Cannot validate the deployment, please retry in few minutes and if the problem persists contact the administrators.")
        user_gid = get_user_gid(logger, access_token, username)
        if user_gid is None:
            raise kopf.AdmissionError("Cannot validate the deployment, please retry in few minutes and if the problem persists contact the administrators.")
        logger.debug(f"############# Adding GID {str(user_gid)} to securityContext.supplementalGroups")
        patch.spec['template']['spec']['securityContext']['supplementalGroups'] = [user_gid]
        
        # Check with Dataset Service if the user can use the datasets requested
        access_checked = check_access_dataset(logger, access_token, username, datasets, DATASET_SERVICE_ENDPOINT)
        if len(access_checked["denied"])>0:
            logger.warning(f"User {username} is trying to use dataset(s) that is not allowed or not exist: " + str(access_checked["denied"]))
            if access_checked['return_code'] == 403 and len(access_checked["granted"]) == 0 and DATASET_SERVICE_TEST_ENDPOINT != None:
                logger.warning("############# Trying to check the access in the Dataset-service test endpoint...")
                # This is needed to synchronize the DB of the test service with the production DB which is the "master" provider of user GIDs.
                put_user_gid_in_test_dataset_service(logger, access_token, username, user_gid)
                access_checked = check_access_dataset(logger, access_token, username, datasets, DATASET_SERVICE_TEST_ENDPOINT)
                if len(access_checked["denied"])>0:
                    raise kopf.AdmissionError("Access denied to the following datasets: " + str(access_checked["denied"]))
                else:
                    testingEnvironment = True
                    logger.debug("############# Changing paths of volumes (datalake and datasets) for testing environment")
                    patch.spec['template']['spec']['volumes'] = spec['template']['spec']['volumes']
                    for vol in patch.spec['template']['spec']['volumes']:
                        if vol['name'] == 'datalake':
                            vol['cephfs']['path'] = "/datalake-test"
                        if str(vol['cephfs']['path']).startswith('/datasets/'):
                            vol['cephfs']['path'] = "/datasets-test/"+vol['name']
            else:
                raise kopf.AdmissionError("Access denied to the following datasets: " + str(access_checked["denied"]))

    # Store some info required later
    newAnnotations = {}
    newAnnotations[ANNOTATION_USERNAME] = username
    newAnnotations[ANNOTATION_TESTING_ENVIRONMENT] = str(testingEnvironment)
    if ANNOTATION_CREATE_GUACAMOLE_CONNECTION in annotations and str(annotations[ANNOTATION_CREATE_GUACAMOLE_CONNECTION]).strip().lower() == 'true' \
        and not ANNOTATION_GUACAMOLE_CONNECTION_NAME in annotations:
        newAnnotations[ANNOTATION_GUACAMOLE_CONNECTION_NAME] = datetime.today().strftime('%Y-%m-%d-%H-%M-%S') + "---" + name
    logger.debug("############# Adding annotations: " + json.dumps(dict(newAnnotations)))
    patch.metadata['annotations'] = newAnnotations

# def validate_dataset_access(spec, logger, userinfo, body, warnings, headers, uid, annotations):
#     _spec = dict(spec)
    
#     if "securityContext" not in _spec["template"]["spec"]:
#         raise kopf.AdmissionError("Missing spec.securityContext in the Deployment.")

#     if not "supplementalGroups" in _spec["template"]["spec"]["securityContext"]:
#         raise kopf.AdmissionError("Missing spec.securityContext.supplementalGroups.")

#     supplementalGroups = _spec["template"]["spec"]["securityContext"]["supplementalGroups"]
#     if not isinstance(supplementalGroups, list) or len(supplementalGroups) != 1:
#         raise kopf.AdmissionError("The property spec.securityContext.supplementalGroups must be a list with one element.")

#     gid = supplementalGroups[0]
#     datasets = annotations[ANNOTATION_DATASETS_IDS].replace(" ", "").split(",")
#     # testingDatalake = ("chaimeleon.eu/testingDatalake" in annotations 
#     #                    and str(annotations["chaimeleon.eu/testingDatalake"]).strip().lower() == 'true')
#     toolName = annotations[ANNOTATION_TOOL_NAME].replace(" ", "")
#     toolVersion = annotations[ANNOTATION_TOOL_VERSION].replace(" ", "")

#     keycloak_username = userinfo['username'][ len(K8S_USER_PREFIX): ]    # Remove Kubernetes prefix for username

#     if not isinstance(datasets, list):
#         raise kopf.AdmissionError(f"The annotation '{ANNOTATION_DATASETS_IDS}' must be a list of datasetsIDs sepparated with ','")

#     logger.debug("Starting validation uid={} -> username={}, toolName={}, toolVersion={}, providedGID={}, datasets={}" 
#                  .format(uid, keycloak_username, toolName, toolVersion, str(gid), str(datasets)))  #, ", testingDatalake = true" if testingDatalake else ""))

#     if len(datasets) == 0:
#         logger.info(f"uid={uid} -> User {keycloak_username} will deploy toolName={toolName} without datasets")
#     else:
#         access_token = get_access_token(logger)
#         if not access_token:
#             raise kopf.AdmissionError("Cannot validate the deployment, please contact the administrators")
        
#         # Check if the GID provided by the user is correct
#         user_gid = get_user_gid(logger, access_token, keycloak_username)
#         if user_gid is None or not int(gid) == user_gid:
#             logger.warning(f"uid={uid} -> User {keycloak_username} is trying to use another GID than the GID obtained from Dataset Service")
#             raise kopf.AdmissionError("Access denied because you are using an unauthorized supplementalGroup for you. "
#                                       "Please contact CHAIMELEON administrators to solve it.")

#         # Check with Dataset Service if the user can use the datasets requested
#         access_checked = check_access_dataset(logger, access_token, keycloak_username, datasets, DATASET_SERVICE_ENDPOINT)
#         if len(access_checked["denied"])>0:
#             logger.warning(f"uid={uid} -> User {keycloak_username} is trying to use dataset(s) that is not allowed or not exist: " + str(access_checked["denied"]))
#             if access_checked['return_code'] == 403 and len(access_checked["granted"]) == 0 and DATASET_SERVICE_TEST_ENDPOINT != None:
#                 logger.warning("Trying to check the access in the Dataset-service test endpoint...")
#                 #logger.debug("##### USERINFO: " + json.dumps(userinfo))
#                 #user_uid = userinfo["sub"]
#                 # This is needed to synchronize the DB of the test service with the production DB which is the "master" provider of user GIDs.
#                 put_user_gid_in_test_dataset_service(logger, access_token, keycloak_username, user_gid)
#                 access_checked = check_access_dataset(logger, access_token, keycloak_username, datasets, DATASET_SERVICE_TEST_ENDPOINT)
#                 if len(access_checked["denied"])>0:
#                     raise kopf.AdmissionError("Access denied to the following datasets: " + str(access_checked["denied"]))
#             else:
#                 raise kopf.AdmissionError("Access denied to the following datasets: " + str(access_checked["denied"]))

#         logger.debug(f"Validation uid={uid} ended successfully")

def notify_dataset_access(spec, name, namespace, logger, body, uid, annotations):
    logger.debug("############# ANNOTATIONS: " + json.dumps(dict(annotations)))
    datasets =           annotations[ANNOTATION_DATASETS_IDS].replace(" ", "").split(",")
    username =           annotations[ANNOTATION_USERNAME]
    testingEnvironment = bool(annotations[ANNOTATION_TESTING_ENVIRONMENT])
    toolName =           annotations[ANNOTATION_TOOL_NAME].replace(" ", "")
    toolVersion =        annotations[ANNOTATION_TOOL_VERSION].replace(" ", "")
    access_token = get_access_token(logger)
    ok = access_dataset(logger, access_token, uid, username, datasets, toolName, toolVersion, testingEnvironment)
    log_text = ("uid={} -> Access dataset {}successfully notified: User={}, tool={}:{} , datasets={}{}"
                .format(uid, "" if ok else "un", username, toolName, toolVersion, str(datasets), ", (testingEnvironment)" if testingEnvironment else ""))
    if ok: logger.info(log_text)
    else: logger.error(log_text)
    
def notify_end_of_dataset_access(spec, name, namespace, logger, body, uid, annotations):
    logger.debug("############# ANNOTATIONS: " + json.dumps(dict(annotations)))
    datasets =           annotations[ANNOTATION_DATASETS_IDS].replace(" ", "").split(",")
    username =           annotations[ANNOTATION_USERNAME] if ANNOTATION_USERNAME in annotations else "unknown"
    testingEnvironment = bool(annotations[ANNOTATION_TESTING_ENVIRONMENT]) if ANNOTATION_TESTING_ENVIRONMENT in annotations else False
    toolName =           annotations[ANNOTATION_TOOL_NAME].replace(" ", "")
    toolVersion =        annotations[ANNOTATION_TOOL_VERSION].replace(" ", "")
    access_token = get_access_token(logger)
    ok = finalise_access_dataset(logger, access_token, uid, testingEnvironment)
    log_text = ("uid={} -> End of dataset access {}successfully notified: User={}, tool={}:{} , datasets:{}{}"
                .format(uid, "" if ok else "un", username, toolName, toolVersion, str(datasets), ", (testingEnvironment)" if testingEnvironment else ""))
    if ok: logger.info(log_text)
    else: logger.error( log_text )

def get_access_token(logger):
    URL = f"{KEYCLOAK_ENDPOINT}/auth/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    data = {"client_id": KEYCLOAK_CLIENT, "client_secret": KEYCLOAK_CLIENT_SECRET, "grant_type": "client_credentials"}
    response = do_request(URL, "POST", logger, KEYCLOAK_MAX_RETRIES, data=data, verify=True)

    if response is None: return None
    if response.status_code == 200:
        return response.json()['access_token']
    else:
        logger.error(f"Cannot obtain the access_token for client {KEYCLOAK_CLIENT}. Response: status_code={response.status_code}, text={response.text}")
        return None

def check_access_dataset(logger, access_token, username, datasets_list, dataset_service_endpoint):
    result = { 'granted': [], 'denied': [] }
    URL = f"{dataset_service_endpoint}/api/datasetAccessCheck"
    data = { "userName": username, "datasets": datasets_list }
    headers= { "Content-Type": "application/json", "Accept": "application/json", "Authorization": "bearer " + access_token }

    response =  do_request(URL, "POST", logger, DATASET_SERVICE_MAX_RETRIES, headers=headers, data=json.dumps(data), verify=False)

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
             logger.error("Invalid access token used at --check_access_dataset-- function: " + response.text)
         else:
             logger.error("Error at --check_access_dataset-- function: " + response.text)

    result['return_code'] = response.status_code
    return result

def get_user_gid(logger, access_token, username):
    URL = f"{DATASET_SERVICE_ENDPOINT}/api/users/{username}"
    headers = { "Content-Type": "application/json", "Accept": "application/json", "Authorization": "bearer " + access_token }
    response =  do_request(URL, "GET", logger, DATASET_SERVICE_MAX_RETRIES, headers=headers, verify=False)

    if response is None: return None
    if response.status_code == 200:
        return int(response.json()['gid'])
    else:
        if response.status_code == 404:
            logger.error(f"User {username} not found in Dataset Service: " + response.text)
        else: logger.error("Error at --get_user_gid-- function: " + response.text)
        return None

def put_user_gid_in_test_dataset_service(logger, access_token, username, user_gid):
    URL = f"{DATASET_SERVICE_TEST_ENDPOINT}/api/users/{username}"
    headers = { "Content-Type": "application/json", "Accept": "application/json", "Authorization": "bearer " + access_token }
    data = { "groups": [], "gid": user_gid }
    response =  do_request(URL, "PUT", logger, DATASET_SERVICE_MAX_RETRIES, headers=headers, data=json.dumps(data), verify=False)
    if response is None: 
        logger.error("There is no response from " + URL)
        return
    if response.status_code == 201:  # OK, success
        logger.debug(f"User GID {user_gid} inserted in the test dataset service for the user {username}")
    else:
        logger.error(f"Error at --put_user_gid_in_test_dataset_service-- function: ({response.status_code}) {response.text}")

def access_dataset(logger, access_token, id, username, datasets_list, toolName, toolVersion, testingDatalake):
    endpoint = DATASET_SERVICE_TEST_ENDPOINT if testingDatalake else DATASET_SERVICE_ENDPOINT
    URL = f"{endpoint}/api/datasetAccess/{id}"
    data = { "userName": username, "datasets": datasets_list, "toolName": toolName, "toolVersion": toolVersion }
    headers = { "Content-Type": "application/json", "Accept": "application/json", "Authorization": "bearer " + access_token }
    logger.debug( f"uid={id} -> User {username} with {toolName}:{toolVersion} is using the following datasets: {str(datasets_list)}" )
    response =  do_request(URL, "POST", logger, DATASET_SERVICE_MAX_RETRIES, headers=headers, data=json.dumps(data), verify=False)

    if response.status_code == 201:
        return True
    else:
        if response.status_code == 401:
            logger.error("Invalid access token used at --access_dataset-- function: " + response.text) 
        return False

def finalise_access_dataset(logger, access_token, id, testingDatalake):
    endpoint = DATASET_SERVICE_TEST_ENDPOINT if testingDatalake else DATASET_SERVICE_ENDPOINT
    URL = f"{endpoint}/api/datasetAccess/{id}"
    headers= { "Content-Type": "application/json", "Accept": "application/json", "Authorization": "bearer " + access_token }
    response = do_request(URL, "DELETE", logger, DATASET_SERVICE_MAX_RETRIES, headers=headers, verify=False)

    if response is None: return False
    if response.status_code == 204:
        logger.debug( f"uid={id} -> Dataset access successfully deleted by Dataset service" )
        return True
    else:
        if response.status_code == 401:
            logger.error("Invalid access token used at --finalise_access_dataset-- function: " + str(response.text))
        else:
            logger.error("Error at --finalise_access_dataset-- function: " + str(response.text))
        return False

def do_request(URL, method, logger, max_retries, data=None, headers=None, verify=True):
    current_retries = 0
    while (current_retries < max_retries) :
        current_retries += 1
        try: 
            return requests.request(method, URL, data=data, verify=verify, headers=headers)
        except requests.exceptions.ConnectionError:
            logger.warning(f"Cannot connect to {URL}, waiting 1 seconds...")
            time.sleep(1)
        except Exception as e:
            logger.warning("Unexpected exception " + str(e) )
    logger.error(f"Cannot connect to {URL} (retries = {max_retries})")
    return None
