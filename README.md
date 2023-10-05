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
 - `chaimeleon.eu/persistentHomeMountPoint: "<mount point for persistent-home>"`
   It is optional, if not exists then the persistent-home will not be mounted.
 - `chaimeleon.eu/persistentSharedFolderMountPoint: "<mount point for persistent-shared-folder>"`
   It is optional, if not exists then the persistent-shared-folder will not be mounted.
 - `chaimeleon.eu/datasetsIDs: "<coma-separated list of dataset IDs"`
   It is optional, if not exists or empty then no dataset will be mounted nor the datalake volume.
   If there is one o more datasets requested, then the datalake will be mounted additionally in `/mnt/datalake`.
 - `chaimeleon.eu/datasetsMountPoint: "<mount point for datasets directory>"`
   It is optional, default value: `/home/chaimeleon/datasets`.

