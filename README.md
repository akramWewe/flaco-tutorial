# before the demo

```{r klippy, echo=FALSE, include=TRUE}
brew upgrade eksctl && { brew link --overwrite eksctl; } || { brew tap weaveworks/tap; brew install weaveworks/tap/eksctl; }
```

## install cluster eks

```{r klippy, echo=FALSE, include=TRUE}
eksctl create cluster -f cluster.yaml
kubectl get node
kubectl get pods -A -o wide
```

## Création du rôle IAM du pilote CSI Amazon EBS
```{r klippy, echo=FALSE, include=TRUE}
eksctl utils associate-iam-oidc-provider --region=eu-west-3 --cluster=weshare-poc --approve
```

```{r klippy, echo=FALSE, include=TRUE}
eksctl create iamserviceaccount \
  --name ebs-csi-controller-sa \
  --namespace kube-system \
  --cluster weshare-poc \
  --attach-policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy \
  --approve \
  --role-only \
  --role-name AmazonEKS_EBS_CSI_DriverRole
```

```{r klippy, echo=FALSE, include=TRUE}
eksctl create addon --name aws-ebs-csi-driver --cluster weshare-poc --service-account-role-arn arn:aws:iam::247820458629:role/AmazonEKS_EBS_CSI_DriverRole --force
```

## Clean up falco 

```{r klippy, echo=FALSE, include=TRUE}
helm list -n falco
helm uninstall falco -n falco
```

# Install falco  chart Helm directly

```{r klippy, echo=FALSE, include=TRUE}
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
```

```{r klippy, echo=FALSE, include=TRUE}
helm install falco \
  --create-namespace \
  --namespace falco \
  --set tty=true \
  falcosecurity/falco
```

```{r klippy, echo=FALSE, include=TRUE}
kubectl get pods -n falco -w
```

# Test falco is installed

## Test falco works fine 
```{r klippy, echo=FALSE, include=TRUE}
kubectl logs -l app.kubernetes.io/name=falco -n falco  --all-containers
```

## Get default installed driver

```{r klippy, echo=FALSE, include=TRUE}
kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco-driver-loader --tail=-1 | grep "* Success"
```

## Look for the rules (Two rules maximum) installed by default with Falco 
https://github.com/falcosecurity/rules/blob/c558fc7d2d02cc2c2edc968fe5770d544f1a9d55/rules/falco_rules.yaml


# Test first rule 
Split the therminal
## First terminal: Output logs

```{r klippy, echo=FALSE, include=TRUE}
kubectl logs -l app.kubernetes.io/name=falco -n falco -f --all-containers
```

## Second terminal: Install privileged pod and ssh to it

```{r klippy, echo=FALSE, include=TRUE}
kubectl create -f privileged-pod-1.yaml
```

```{r klippy, echo=FALSE, include=TRUE}
kubectl exec -it test-pod-1 bash -n demo
```

# Activate ebpf  activated and install falcosidekick

```{r klippy, echo=FALSE, include=TRUE}
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
```
## Verify deployment is ok and falcosidekick is exposed

```{r klippy, echo=FALSE, include=TRUE}
kubectl -n falco get svc
```

## Verify the driver is updated 

```{r klippy, echo=FALSE, include=TRUE}
kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco-driver-loader --tail=-1 | grep "* Success" 
```

## Test the deployment of Falcosidekick with a port forward:

```{r klippy, echo=FALSE, include=TRUE}
kubectl port-forward svc/falco-falcosidekick-ui -n falco 2802
```

## See events with falcosidekick UI

Navigate to http://locahost:2802, login:admin & password:admin and see last events in falcosidekick UI

# Test Some Threats

MITRE ATTACK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.
These ATTACKS are represented here: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics

```{r klippy, echo=FALSE, include=TRUE}
kubectl exec -ti atomicred-5cc5c7996c-4vgfc -n demo -- /bin/bash
```

## Start PowerShell & load the Atomic Red Team module

```{r klippy, echo=FALSE, include=TRUE}
pwsh
```

```{r klippy, echo=FALSE, include=TRUE}
Import-Module "~/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1" -Force
```
 
## Rule Falco: Write below etc
```{r klippy, echo=FALSE, include=TRUE}
Invoke-AtomicTest T1037.004 -ShowDetails
```

```{r klippy, echo=FALSE, include=TRUE}
Invoke-AtomicTest T1037.004
```

```{r klippy, echo=FALSE, include=TRUE}
Invoke-AtomicTest T1037.004 -CleanUp
```


## Rule Falco: Read sensitive file untrusted

```{r klippy, echo=FALSE, include=TRUE}
Invoke-AtomicTest T1003.008
```

## Rules Falco: Write below root  & Launch Suspicious Network Tool in Container

```{r klippy, echo=FALSE, include=TRUE}
Invoke-AtomicTest T1040 -GetPreReqs
```

```{r klippy, echo=FALSE, include=TRUE}
Invoke-AtomicTest T1040
```

```{r klippy, echo=FALSE, include=TRUE}
Invoke-AtomicTest T1040 -CleanUp
```

## Rule Falco: Clear Log Activities

```{r klippy, echo=FALSE, include=TRUE}
Invoke-AtomicTest T1070.002
```

## Rule : Search Private Keys or Passwords

```{r klippy, echo=FALSE, include=TRUE}
Invoke-AtomicTest T1552.004
```

## Rule : rule The docker client is executed in a container

```{r klippy, echo=FALSE, include=TRUE}
Invoke-AtomicTest T1552.007 -GetPreReqs
```

## Rule: Test threats present directly in the host
Exit for container, SSH to the EC2 node from the console and verify Slack falco-alerts chanel + falcosidekick UI

## Optional fo Weshare Rule: Launch Remote File Copy Tools in Container

```{r klippy, echo=FALSE, include=TRUE}
Invoke-AtomicTest T1105
```

## Optional for Wehsare: Rules Falco: Read sensitive file untrusted && Launch Package Management Process in Container && Read environment variable from /proc files

```{r klippy, echo=FALSE, include=TRUE}
Invoke-AtomicTest T1059.004 -GetPreReqs
```

```{r klippy, echo=FALSE, include=TRUE}
Invoke-AtomicTest T1059.004
```

```{r klippy, echo=FALSE, include=TRUE}
Invoke-AtomicTest T1059.004 -CleanUp
```

## Optional Rules Falco: Write below root and Clear Log Activities and Delete Bash History & Modify Shell Configuration File

```{r klippy, echo=FALSE, include=TRUE}
Invoke-AtomicTest T1070.003
```

```{r klippy, echo=FALSE, include=TRUE}
Invoke-AtomicTest T1070.003 -CleanUp
```

## Optional Rule Falco: Remove Bulk Data from Disk and Write below root and Modify Shell Configuration File and Delete Bash History  and Delete or rename shell history && Modify Shell Configuration File

```{r klippy, echo=FALSE, include=TRUE}
Invoke-AtomicTest T1070.004   
```

```{r klippy, echo=FALSE, include=TRUE}
Invoke-AtomicTest T1070.004 -CleanUp
```


# Add Custom rule
## Look for the new rules > custom-rules.yaml
## Create Helm value containing the custom rule

```{r klippy, echo=FALSE, include=TRUE}
curl https://raw.githubusercontent.com/tosokr/falco-custom-rules/main/rules2helm.sh > rules2helm.sh
```

```{r klippy, echo=FALSE, include=TRUE}
./rules2helm.sh custom-rules/custom-rules.yaml  custom-rules/ingress-nginx.yaml > custom-rules.yaml
```

##  Upgrade Falco rules with custom-rules.yaml

```{r klippy, echo=FALSE, include=TRUE}
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
```

```{r klippy, echo=FALSE, include=TRUE}
kubectl get pod -n falco -w
```

## Test falco works fine 

```{r klippy, echo=FALSE, include=TRUE}
kubectl logs -l app.kubernetes.io/name=falco -n falco  --all-containers
```

## Test Rule custom: Text Editor Run by Root 

```{r klippy, echo=FALSE, include=TRUE}
kubectl exec -it test-pod-1 -n demo bash
```

```{r klippy, echo=FALSE, include=TRUE}
vi /test 
```

```{r klippy, echo=FALSE, include=TRUE}
See event in Slack (Falco-alerts + falcosidekick UI)
```

# Intall plugin https://github.com/falcosecurity/plugins/tree/master/plugins/github

## Try to install plugin k8saudit
## Look to rules k8s audit
## https://github.com/falcosecurity-retire/falco-security-workshop/blob/master/exercise2/k8s-using-daemonset/k8s-with-rbac/falco-config/k8s_audit_rules.yaml
## Look to values-k8saudit.yaml (two rules maximum) and the value plugins file

```{r klippy, echo=FALSE, include=TRUE}
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
```

## !!! Not event detected ? Why >> Go back to slides








