## CHAIMELEON Kubernetes operator


Once you prepared the YAML with the variables in the values.yaml file, you can install it using the command:

helm install chaimeleon-operator ./chaimeleon-operator-chart -f installation-values.yml --namespace chaimeleon-operator --create-namespace 