
This document describes the learning, installation and application deployment of kubernetes.

k8s单机版部署

1.关闭swap

# vim /etc/fstab
# units generated from this file.
#
/dev/mapper/almalinux-root /                       xfs     defaults        0 0
UUID=82427f8d-af8d-4018-8b10-6e6aa7d34c91 /boot                   xfs     defaults        0 0
/dev/mapper/almalinux-home /home                   xfs     defaults        0 0
#/dev/mapper/almalinux-swap none                    swap    defaults        0 0

注释掉swap;
临时关闭：swapoff -a;

2.关闭selinux
# vim /etc/sysconfig/selinux
设置SELINUX=disabled，需要重启reboot。

#     disabled - No SELinux policy is loaded.
SELINUX=disabled
# SELINUXTYPE= can take one of these three values:
#     targeted - Targeted processes are protected,
#     minimum - Modification of targeted policy. Only selected processes are protected.
#     mls - Multi Level Security protection.
SELINUXTYPE=targeted


3.关闭防火墙 

systemctl stop firewalld
systemctl disable firewalld

4.启用网络配置

# vim /proc/sys/net/bridge/bridge-nf-call-iptables
1
或
echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables

5.设置网桥参数

# vim /etc/sysctl.d/k8s.conf

net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1

或
修改内核参数和模块

cat << EOF > /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
EOF

另外一种修改如下：
cat <<EOF > /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF

#使内核参数配置生效
sysctl --system
modprobe br_netfilter
lsmod | grep br_netfilter


6.修改hosts文件

# vim /etc/hosts

127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
192.168.126.129 K8s
设置： 192.168.126.129 K8s

7.修改hostname

hostnamectl set-hostname K8s
或
hostnamectl --static set-hostname master

# hostnamectl
   Static hostname: K8s
         Icon name: computer-vm
           Chassis: vm
        Machine ID: 8166aec4bed44a88947523231a677fbd
           Boot ID: c9c15753899b40cda8239c9ceed9597d
    Virtualization: vmware
  Operating System: AlmaLinux 8.7 (Stone Smilodon)
       CPE OS Name: cpe:/o:almalinux:almalinux:8::baseos
            Kernel: Linux 4.18.0-425.3.1.el8.x86_64
      Architecture: x86-64
#


8.安装docker
yum -y install yum-utils device-mapper-persistent-data lvm2

yum-config-manager -y --add-repo https://download.docker.com/linux/centos/docker-ce.repo
yum -y install docker-ce-18.06.3.ce-3.el7 docker-ce-cli-18.06.3.ce-3.el7 containerd.io

systemctl start docker
systemctl enable docker

Docker Server Version: 20.10.21

9.设置国内docker仓库

cat <<EOF > /etc/docker/daemon.json
{
  "registry-mirrors": ["https://3laho3y3.mirror.aliyuncs.com"]
}
EOF

systemctl restart docker

10.配置kubernetes yum源，用以安装Kubernetes基础服务及工具，此处使用阿里云镜像仓库源。

创建文件：/etc/yum.repos.d/kubernetes.repo   
#内容为：

cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://mirrors.aliyun.com/kubernetes/yum/doc/yum-key.gpg https://mirrors.aliyun.com/kubernetes/yum/doc/rpm-package-key.gpg
EOF


11.安装 Kubernetes 基础服务及工具
安装 kubelet kubeadm kubectl

yum install -y --nogpgcheck kubelet-1.26.1 kubeadm-1.26.1 kubectl-1.26.1

systemctl start kubelet.service
systemctl enable kubelet.service

# systemctl status kubelet.service
● kubelet.service - kubelet: The Kubernetes Node Agent
   Loaded: loaded (/usr/lib/systemd/system/kubelet.service; enabled; vendor preset: disabled)
  Drop-In: /usr/lib/systemd/system/kubelet.service.d
           └─10-kubeadm.conf
   Active: active (running) since Sat 2023-02-04 12:48:25 CST; 1h 45min ago
     Docs: https://kubernetes.io/docs/
 Main PID: 17002 (kubelet)
    Tasks: 13 (limit: 23340)
   Memory: 53.7M
   CGroup: /system.slice/kubelet.service
           └─17002 /usr/bin/kubelet --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf --config=/var/lib/kubelet/config.yaml --container>
           
           
# kubelet --version
Kubernetes v1.26.1
[root@K8s ~]#
[root@K8s ~]# kubectl version
WARNING: This version information is deprecated and will be replaced with the output from kubectl version --short.  Use --output=yaml|json to get the full version.
Client Version: version.Info{Major:"1", Minor:"26", GitVersion:"v1.26.1", GitCommit:"8f94681cd294aa8cfd3407b8191f6c70214973a4", GitTreeState:"clean", BuildDate:"2023-01-18T15:58:16Z", GoVersion:"go1.19.5", Compiler:"gc", Platform:"linux/amd64"}
Kustomize Version: v4.5.7
The connection to the server 192.168.126.129:6443 was refused - did you specify the right host or port?
[root@K8s ~]#
[root@K8s ~]# kubeadm version
kubeadm version: &version.Info{Major:"1", Minor:"26", GitVersion:"v1.26.1", GitCommit:"8f94681cd294aa8cfd3407b8191f6c70214973a4", GitTreeState:"clean", BuildDate:"2023-01-18T15:56:50Z", GoVersion:"go1.19.5", Compiler:"gc", Platform:"linux/amd64"}
[root@K8s ~]#

启动kubelet
systemctl daemon-reload
systemctl start kubelet.service
systemctl enable kubelet


12.下载k8s相关镜像并打标签

# kubeadm config images list  &&  kubeadm config images pull --config=init-config.yaml
registry.k8s.io/kube-apiserver:v1.26.1
registry.k8s.io/kube-controller-manager:v1.26.1
registry.k8s.io/kube-scheduler:v1.26.1
registry.k8s.io/kube-proxy:v1.26.1
registry.k8s.io/pause:3.9
registry.k8s.io/etcd:3.5.6-0
registry.k8s.io/coredns/coredns:v1.9.3

#或者

for i in `kubeadm config images list`; do 
  imageName=${i#k8s.gcr.io/}
  docker pull registry.aliyuncs.com/google_containers/$imageName
  docker tag registry.aliyuncs.com/google_containers/$imageName k8s.gcr.io/$imageName
  docker rmi registry.aliyuncs.com/google_containers/$imageName
done;

另外的写法：
for i in `kubeadm config images list --config=init-config.yaml`; do 
  imageName=${i#registry.k8s.io/}
  docker pull $imageName
done;



13. 生成 init-config 配置文件
kubeadm config print init-defaults > init-config.yaml

# cat init-config.yaml
apiVersion: kubeadm.k8s.io/v1beta3
bootstrapTokens:
- groups:
  - system:bootstrappers:kubeadm:default-node-token
  token: abcdef.0123456789abcdef
  ttl: 24h0m0s
  usages:
  - signing
  - authentication
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: 192.168.126.129
  bindPort: 6443
nodeRegistration:
  criSocket: unix:///var/run/containerd/containerd.sock
  imagePullPolicy: IfNotPresent
  name: master
  taints: null
---
apiServer:
  timeoutForControlPlane: 4m0s
apiVersion: kubeadm.k8s.io/v1beta3
certificatesDir: /etc/kubernetes/pki
clusterName: kubernetes
controllerManager: {}
dns: {}
etcd:
  local:
    dataDir: /var/lib/etcd
imageRepository: registry.aliyuncs.com/google_containers
kind: ClusterConfiguration
kubernetesVersion: 1.26.1
networking:
  dnsDomain: cluster.local
  serviceSubnet: 10.96.0.0/12
scheduler: {}
#
#

配置IP地址：localAPIEndpoint.advertiseAddress: 192.168.126.129

配置node的名称：nodeRegistration.name:master

配置阿里云镜像地址：imageRepository：registry.aliyuncs.com/google_containers




14.初始化k8s和网络

kubeadm init --apiserver-advertise-address=192.168.126.129 --image-repository registry.aliyuncs.com/google_containers --kubernetes-version v1.26.1 --service-cidr=10.96.0.0/12 --pod-network-cidr=10.244.0.0/16

#或简单初始化

kubeadm init --kubernetes-version=v1.26.1 --pod-network-cidr=10.244.0.0/16

#安装成功标志
#Your Kubernetes master has initialized successfully!

#开机启动 && 启动服务

systemctl enable kubelet && systemctl start kubelet


15.初始化kubectl配置

mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
 
kubectl apply -f https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')

配置环境变量：

echo "export KUBECONFIG=/etc/kubernetes/admin.conf" >> /etc/profile；
source /etc/profile；

上面的方式，重启机器后会失效，持久的方式：
vi /etc/profile；
在后面新增一行：export KUBECONFIG=/etc/kubernetes/admin.conf

最后source /etc/profile；


16.默认k8s的master节点是不能跑pod的业务，需要执行以下命令解除限制。

kubectl taint nodes --all node-role.kubernetes.io/master-

#如果不允许调度
#kubectl taint nodes master1 node-role.kubernetes.io/master=:NoSchedule
#污点可选参数
      NoSchedule: 一定不能被调度
      PreferNoSchedule: 尽量不要调度
      NoExecute: 不仅不会调度, 还会驱逐Node上已有的Pod



17.查看主节点运行 Pod 的状态
kubectl get pods --all-namespaces -o wide









参考链接

https://huaweicloud.csdn.net/63311cd8d3efff3090b528a4.html?spm=1001.2101.3001.6650.2&utm_medium=distribute.pc_relevant.none-task-blog-2~default~BlogCommendFromBaidu~activity-2-121419041-blog-122775140.pc_relevant_vip_default&depth_1-utm_source=distribute.pc_relevant.none-task-blog-2~default~BlogCommendFromBaidu~activity-2-121419041-blog-122775140.pc_relevant_vip_default&utm_relevant_index=3

https://blog.csdn.net/zhengbinggui/article/details/127766664

https://blog.csdn.net/qq_42999835/article/details/122775140

https://www.jianshu.com/p/0183fb9c1dd0

https://blog.csdn.net/love_THL/article/details/128332247














