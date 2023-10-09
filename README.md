## CHAIMELEON Kubernetes operator

### Build and upload the image

```
set IMAGE_NAME=harbor.chaimeleon-eu.i3m.upv.es/chaimeleon-services/k8s-operator
set /p IMAGE_TAG=< VERSION

docker build -t %IMAGE_NAME%:%IMAGE_TAG% .

docker push %IMAGE_NAME%:%IMAGE_TAG%
```

### Install the helm chart

Once you prepared the YAML with the variables in the values.yaml file, you can install it using the command:
```
helm install chaimeleon-operator ./chaimeleon-operator-chart -f installation-values.yml --namespace chaimeleon-operator --create-namespace 
```

### Known annotations in Deployments and Jobs

Annotations for mounting CHAIMELEON volumes:
 - **persistent-home**  
   `chaimeleon.eu/persistentHomeMountPoint: "<mount point for persistent-home>"`  
   It is optional, if not exists then the persistent-home will not be mounted.  
   Example: `chaimeleon.eu/persistentHomeMountPoint: "/home/chaimeleon/persistent-home"`
 - **persistent-shared-folder**  
   `chaimeleon.eu/persistentSharedFolderMountPoint: "<mount point for persistent-shared-folder>"`  
   It is optional, if not exists then the persistent-shared-folder will not be mounted.  
   Example: `chaimeleon.eu/persistentSharedFolderMountPoint: "/home/chaimeleon/persistent-shared-folder"`
 - **datasets and datalake**  
   `chaimeleon.eu/datasetsIDs: "<coma-separated list of dataset IDs>"`  
   It is optional, if not exists or empty then no dataset will be mounted nor the datalake volume.  
   If there is one o more datasets requested, then the datalake will be mounted additionally in `/mnt/datalake`.  
   Example: `chaimeleon.eu/datasetsIDs: "f5ac09a4-1e5d-4d0d-a59d-9e3343ca4012, 2a78efbd-dbfa-4224-b61b-5192fc6c6a1c"`  
   `chaimeleon.eu/datasetsMountPoint: "<mount point for datasets directory>"`  
   It is optional, default value: `/home/chaimeleon/datasets`.  
   Example: `chaimeleon.eu/datasetsMountPoint: "/home/chaimeleon/datasets"`

 - **guacamole connection** (for remote desktops)
   `chaimeleon.eu/createGuacamoleConnection: "true"`
   It is optional, if exist then there must be also a Secret in the same namespace, with the same name of the deployment 
   and containing the following entries:
    - `container-user`: Optional, default value is "chaimeleon". The username for connecting to the SFTP/SSH server
    - `container-password`: the password for connecting to the VNC server and the SFTP/SSH server.

