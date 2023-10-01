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
