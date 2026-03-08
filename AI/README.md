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

If you're runing on a GPU, here are some checks:
kubectl logs -n kube-system -l name=nvidia-device-plugin-ds
kubectl describe node my-node-name | grep -A 8 Capacity


And FYI, here is the complete story of this experience, trying to make open-webui working on my old gaming laptop...work in IT they said, it will be fun... :-)

I spent my Sunday getting a GTX 870M to work under Kubernetes. Here's what I learned.

It started with a simple `nvidia-smi` returning an error. What looked like a 5-minute fix turned into a deep dive into the guts of Linux, Nvidia drivers, and K3s.

The diagnosis
Kernel 6.17 (very recent) was installed, but the GTX 870M is a "legacy" GPU that only supports the Nvidia 470.xx driver. The 535 driver installed by default was silently ignoring it — `dmesg` made it crystal clear:

"The NVIDIA GeForce GTX 870M is supported through the NVIDIA 470.xx Legacy drivers."

The kernel fix
Fortunately, kernel 6.8.0 LTS was still present on the system. I set it back as default in GRUB and reinstalled the 470 legacy driver — which compiled cleanly via DKMS.

Kubernetes integration (the real adventure)
Getting K3s to recognize the GPU was a whole other story. Several obstacles in a row:
→ nvidia-container-toolkit had to be configured for K3s's embedded containerd, not the system containerd
→ The nvidia-device-plugin couldn't find libnvidia-ml.so.1 without runtimeClassName: nvidia
→ The kubelet.sock socket was nowhere to be found — because K3s uses /var/lib/kubelet/, not the standard Rancher paths

The result
Once I found the right socket path, the device plugin registered successfully and the node now exposes nvidia.com/gpu: 1 — ready to run GPU workloads in the cluster.

Key takeaways
• Always check driver/kernel compatibility BEFORE upgrading
• K3s has its own paths that differ from vanilla Kubernetes
• `dmesg | grep nvidia` is your best friend for GPU debugging
• Every error message is a clue — persistence pays off

An old gaming laptop can absolutely become a GPU node in a homelab. You just need a bit of patience. 💪

#Kubernetes #K3s #Nvidia #Homelab #Linux #DevOps #GPU #SelfHosted