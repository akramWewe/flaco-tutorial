# before the demo
brew upgrade eksctl && { brew link --overwrite eksctl; } || { brew tap weaveworks/tap; brew install weaveworks/tap/eksctl; }

## install cluster eks
eksctl create cluster -f cluster.yaml
kubectl get node
kubectl get pods -A -o wide

## Création du rôle IAM du pilote CSI Amazon EBS

eksctl utils associate-iam-oidc-provider --region=eu-west-3 --cluster=weshare-poc --approve

eksctl create iamserviceaccount \
  --name ebs-csi-controller-sa \
  --namespace kube-system \
  --cluster weshare-poc \
  --attach-policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy \
  --approve \
  --role-only \
  --role-name AmazonEKS_EBS_CSI_DriverRole

  eksctl create addon --name aws-ebs-csi-driver --cluster weshare-poc --service-account-role-arn arn:aws:iam::247820458629:role/AmazonEKS_EBS_CSI_DriverRole --force

## Clean up falco 
helm list -n falco
helm uninstall falco -n falco

# Install falco from chart Helm directly
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco \
  --create-namespace \
  --namespace falco \
  --set tty=true \
  falcosecurity/falco

kubectl get pods -n falco -w

# Test falco is installed

## Test falco works fine 
kubectl logs -l app.kubernetes.io/name=falco -n falco  --all-containers

## Get default installed driver
kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco-driver-loader --tail=-1 | grep "* Success"

## Look for the rules (Two rules maximum) installed by default with Falco >> https://github.com/falcosecurity/rules/blob/c558fc7d2d02cc2c2edc968fe5770d544f1a9d55/rules/falco_rules.yaml

# Test first rule -> Split the therminal in two screen
## Output logs in first terminal
kubectl logs -l app.kubernetes.io/name=falco -n falco -f --all-containers

## In the second terminal, install privileged pod and ssh to it
kubectl create -f privileged-pod-1.yaml
kubectl exec -it test-pod-1 bash -n demo

# Upgrade falco with ebpf  activated & falcosidekick installed
helm upgrade falco \
  --create-namespace \
  --namespace falco \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set falcosidekick.config.slack.webhookurl="https://hooks.slack.com/services/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" \
  --set tty=true \
  --set collectors.containerd.enabled=true \
  --set collectors.containerd.socket=/run/k3s/containerd/containerd.sock \
  --set driver.kind=ebpf \
  falcosecurity/falco

## Verify deployment is ok and falcosidekick is exposed
kubectl -n falco get svc

## Verify the driver is updated 
kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco-driver-loader --tail=-1 | grep "* Success" 

## We can test the deployment of Falcosidekick with a typical port forward:
kubectl port-forward svc/falco-falcosidekick-ui -n falco 2802

## Navigate to http://locahost:2802, login:admin & password:admin and watch last events in falcosidekick UI

# Test Some Threats -->  invoke atomic-read team tests (exec in container atomicred in demo namespace )
# Details of threats >> https://github.com/redcanaryco/atomic-red-team

kubectl exec -ti atomicred-5cc5c7996c-4vgfc -n demo -- /bin/bash

## Start PowerShell & load the Atomic Red Team module
pwsh
Import-Module "~/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1" -Force
 
## Rule Falco: Write below etc
Invoke-AtomicTest T1037.004 -ShowDetails
Invoke-AtomicTest T1037.004
Invoke-AtomicTest T1037.004 -CleanUp


## Rule Falco: Read sensitive file untrusted
Invoke-AtomicTest T1003.008

## Rules Falco: Write below root  & Launch Suspicious Network Tool in Container
Invoke-AtomicTest T1040 -GetPreReqs
Invoke-AtomicTest T1040
Invoke-AtomicTest T1040 -CleanUp

## Rule Falco: Clear Log Activities
Invoke-AtomicTest T1070.002

## Rule : Search Private Keys or Passwords
Invoke-AtomicTest T1552.004

## Rule : rule The docker client is executed in a container
Invoke-AtomicTest T1552.007 -GetPreReqs

## Exit for container, SSH to the EC2 node from the console and verify Slack falco-alerts chanel + falcosidekick UI

## Optional fo Weshare Rule : Launch Remote File Copy Tools in Container
Invoke-AtomicTest T1105

## Optional for Wehsare: Rules Falco: Read sensitive file untrusted && Launch Package Management Process in Container && Read environment variable from /proc files
Invoke-AtomicTest T1059.004 -GetPreReqs
Invoke-AtomicTest T1059.004
Invoke-AtomicTest T1059.004 -CleanUp

## Optional Rule Falco: Write below root & Clear Log Activities & Delete Bash History & Modify Shell Configuration File
Invoke-AtomicTest T1070.003
Invoke-AtomicTest T1070.003 -CleanUp

## Optional Rule Falco: Remove Bulk Data from Disk & Write below root & Modify Shell Configuration File & Delete Bash History & Delete or rename shell history && Modify Shell Configuration File
Invoke-AtomicTest T1070.004   
Invoke-AtomicTest T1070.004 -CleanUp


# Add Custom rule
## Look for the new rules > custom-rules.yaml
## Create Helm value containing the custom rule
curl https://raw.githubusercontent.com/tosokr/falco-custom-rules/main/rules2helm.sh > rules2helm.sh
./rules2helm.sh custom-rules/custom-rules.yaml  custom-rules/ingress-nginx.yaml > custom-rules.yaml

##  Upgrade Falco rules with custom-rules.yaml
helm upgrade falco \
  --namespace falco \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set falcosidekick.config.slack.webhookurl="https://hooks.slack.com/services/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" \
  --set tty=true \
  --set collectors.containerd.enabled=true \
  --set collectors.containerd.socket=/run/k3s/containerd/containerd.sock \
  --set driver.kind=ebpf \
  --values custom-rules.yaml \
  falcosecurity/falco

kubectl get pod -n falco -w

## Test falco works fine 
kubectl logs -l app.kubernetes.io/name=falco -n falco  --all-containers

## Test Rule custom: Text Editor Run by Root 
kubectl exec -it test-pod-1 -n demo bash
vi /test 
See event in Slack (Falco-alerts + falcosidekick UI)

# Intall plugin https://github.com/falcosecurity/plugins/tree/master/plugins/github

## Try to install plugin k8saudit // Rules for 
## Look to rules k8s audit >>
## https://github.com/falcosecurity-retire/falco-security-workshop/blob/master/exercise2/k8s-using-daemonset/k8s-with-rbac/falco-config/k8s_audit_rules.yaml
## Look to values-k8saudit.yaml (two rules maximum) and the value plugins file

helm upgrade falco \
  --namespace falco \
  --values=values-k8saudit.yaml \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set falcosidekick.config.slack.webhookurl="https://hooks.slack.com/services/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" \
  --set tty=true \
  --set collectors.containerd.enabled=true \
  --set collectors.containerd.socket=/run/k3s/containerd/containerd.sock \
  --set driver.kind=ebpf \
  falcosecurity/falco


## !!! Not event detected ? Why >> Go back to slides








