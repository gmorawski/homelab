Open-webui on a Kubernetes cluster with helm.

1- Install k8s or k3s
2- Install and configure helm 
    brew install helm
    helm repo add open-webui https://helm.openwebui.com/
    helm repo update
3- Install open-webui
    helm upgrade --install open-webui open-webui/open-webui -n open-webui --create-namespace -f open-webui-values.yaml
    
ATTENTION, this yaml configuration will expose your cluster IP on port 30990.

More information on Open-webui Git repo:
https://github.com/open-webui/helm-charts/tree/main/charts/open-webui
