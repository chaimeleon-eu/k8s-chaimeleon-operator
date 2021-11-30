## CHAIMELEON Kubernetes operator


Once you prepared the YAML with the variables in the values.yaml file, you can install it using the command:

helm install -f values.yaml --namespace chaimeleon-operator --create-namespace chaimeleon-operator .