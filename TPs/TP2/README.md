# TP2 Containerization in-depth

- [TP2 Containerization in-depth](#tp2-containerization-in-depth)
- [I. Gestion de conteneurs Docker](#i-gestion-de-conteneurs-docker)
- [II. Sandboxing](#ii-sandboxing)
  - [1. Namespaces](#1-namespaces)
    - [A. Exploration manuelle](#a-exploration-manuelle)
    - [B. `unshare`](#b-unshare)
    - [C. Avec docker](#c-avec-docker)
    - [D. `nsenter`](#d-nsenter)
    - [E. Et alors, les namespaces User ?](#e-et-alors-les-namespaces-user)
    - [F. Isolation réseau ?](#f-isolation-r%c3%a9seau)
  - [2. Cgroups](#2-cgroups)
    - [A. Découverte manuelle](#a-d%c3%a9couverte-manuelle)
    - [B. Utilisation par Docker](#b-utilisation-par-docker)
  - [3. Capabilities](#3-capabilities)
    - [A. Découverte manuelle](#a-d%c3%a9couverte-manuelle-1)
    - [B. Utilisation par Docker](#b-utilisation-par-docker-1)
- [III. Conteneurs avec d'autres outils](#iii-conteneurs-avec-dautres-outils)

## I. Gestion de conteneurs Docker

- 🌞 Mettre en évidence l'utilisation de chacun des processus liés à Docker
  - `dockerd`, `containerd`, `containerd-shim`
  - analyser qui est le père de qui (en terme de processus, avec leurs PIDs)
  - avec la commande `ps` par exemple

```shell=
$ ps -ef | grep "shim" && systemctl status docker | grep -A 3 "CGroup" && systemctl status containerd | grep -A 3 "CGroup"
root      2088  1101  0 10:14 ?        00:00:00 containerd-shim -namespace moby -workdir /var/lib/containerd/io.containerd.runtime.v1.linux/moby/f52d379b4b04feb586d9040a4b3e7727834dd684d59b653b41ed255768c0a2b5 -address /run/containerd/containerd.sock -containerd-binary /usr/bin/containerd -runtime-root /var/run/docker/runtime-runc
user      2473  1637  0 10:43 pts/0    00:00:00 grep --color=auto shim
   CGroup: /system.slice/docker.service
           └─1103 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock

Jan 27 09:47:16 localhost.localdomain dockerd[1103]: time="2020-01-27T09:47:16.984992900+01:00" level=info msg="Docker daemon" commit=633a0ea graphdriver(s)=overlay2 version=19.03.5
   CGroup: /system.slice/containerd.service
           ├─1101 /usr/bin/containerd
           └─2088 containerd-shim -namespace moby -workdir /var/lib/containerd/io.containerd.runtime.v1.linux/moby/f52d379b4b04feb586d9040a4b3e7727834dd684d59b653b41ed255768c0a2b5 -address /run/containerd/containerd.sock -containerd-binary /usr/bin/containerd -runtime-root /var/run/docker/runtime-runc
```

> On peut voir que le `shim` est un fils de `containerd` qui lui même utilise `docker` (`dockerd` exécute `containerd` il n'est donc pas son parent.)

---

- 🌞 Utiliser l'API HTTP mise à disposition par `dockerd`
  - utiliser un `curl` (ou autre) pour discuter à travers le socker UNIX
  - la [documentation de l'API est dispo en ligne](https://docs.docker.com/engine/api/v1.40/)
  - récupérer la liste des conteneurs
  - récupérer la liste des images disponibles

```shell=
$ curl --unix-socket /var/run/docker.sock http:/v1.40/containers/json
[...]
$ curl --unix-socket /var/run/docker.sock http:/v1.40/images/json
[...]
```

## II. Sandboxing

Le lancement d'un conteneur se fait dans un environnement sandboxé. Autrement dit :

- il est isolé (vision restreinte des éléments du système, comme les processus ou les utilisateurs)
- il a des restrictions d'accès aux ressources matérielles
- il a des droits restreints
- il est surveillé/monitoré

C'est en grande partie grâce aux fonctionnalités que nous allons voir dans cette partie que ces mesures de sécurité sont en mises en place :

- namespaces
- cgroups
- capabilities
- autres

## 1. Namespaces

### A. Exploration manuelle

🌞 Trouver les namespaces utilisés par votre shell.

> On peut aussi lister l'ensemble des namespaces qui existent sur la machine avec `lsns`

```shell=
$ ps | grep "bash" && ll /proc/1637/ns
 1637 pts/0    00:00:00 bash
total 0
lrwxrwxrwx. 1 user user 0 Jan 27 10:17 ipc -> ipc:[4026531839]
lrwxrwxrwx. 1 user user 0 Jan 27 10:17 mnt -> mnt:[4026531840]
lrwxrwxrwx. 1 user user 0 Jan 27 10:17 net -> net:[4026531956]
lrwxrwxrwx. 1 user user 0 Jan 27 10:17 pid -> pid:[4026531836]
lrwxrwxrwx. 1 user user 0 Jan 27 10:17 user -> user:[4026531837]
lrwxrwxrwx. 1 user user 0 Jan 27 10:17 uts -> uts:[4026531838]
```

### B. `unshare`

🌞 Créer un pseudo-conteneur à la main en utilisant `unshare`

- lancer une commande `unshare`
- `unshare` doit exécuter le processus `bash`
- ce processus doit utiliser des namespaces différents de votre hôte :
  - réseau
  - mount
  - PID
  - user
- prouver depuis votre `bash` isolé que ces namespaces sont bien mis en place

```shell=
$ unshare -f -p -m -n -r -U
#
#
# ps | grep bash
1604 pts/0    00:00:00 bash
5519 pts/0    00:00:00 bash
#
#
# ls -al /proc/5519/ns
total 0
dr-x--x--x. 2 root root 0 Feb  1 20:40 .
dr-xr-xr-x. 9 root root 0 Feb  1 20:40 ..
lrwxrwxrwx. 1 root root 0 Feb  1 20:40 ipc -> ipc:[4026531839]
lrwxrwxrwx. 1 root root 0 Feb  1 20:40 mnt -> mnt:[4026532175]
lrwxrwxrwx. 1 root root 0 Feb  1 20:40 net -> net:[4026532178]
lrwxrwxrwx. 1 root root 0 Feb  1 20:40 pid -> pid:[4026532176]
lrwxrwxrwx. 1 root root 0 Feb  1 20:40 user -> user:[4026532174]
lrwxrwxrwx. 1 root root 0 Feb  1 20:40 uts -> uts:[4026531838]
#
#
# exit
$
$
$ ls -al /proc/1604/ns
total 0
dr-x--x--x. 2 user user 0 Feb  1 20:38 .
dr-xr-xr-x. 9 user user 0 Feb  1 19:29 ..
lrwxrwxrwx. 1 user user 0 Feb  1 20:38 ipc -> ipc:[4026531839]
lrwxrwxrwx. 1 user user 0 Feb  1 20:38 mnt -> mnt:[4026531840]
lrwxrwxrwx. 1 user user 0 Feb  1 20:38 net -> net:[4026531956]
lrwxrwxrwx. 1 user user 0 Feb  1 20:38 pid -> pid:[4026531836]
lrwxrwxrwx. 1 user user 0 Feb  1 20:38 user -> user:[4026531837]
lrwxrwxrwx. 1 user user 0 Feb  1 20:38 uts -> uts:[4026531838]
```

> Seul le namespace `ipc` est identique.

### C. Avec docker

🌞 Trouver dans quels namespaces ce conteneur s'exécute.

```shell=
$ ls -al /proc/3707/ns/
total 0
dr-x--x--x. 2 user user 0 Jan 27 11:48 .
dr-xr-xr-x. 9 user user 0 Jan 27 11:48 ..
lrwxrwxrwx. 1 user user 0 Jan 27 11:48 ipc -> ipc:[4026531839]
lrwxrwxrwx. 1 user user 0 Jan 27 11:48 mnt -> mnt:[4026531840]
lrwxrwxrwx. 1 user user 0 Jan 27 11:48 net -> net:[4026531956]
lrwxrwxrwx. 1 user user 0 Jan 27 11:48 pid -> pid:[4026531836]
lrwxrwxrwx. 1 user user 0 Jan 27 11:48 user -> user:[4026531837]
lrwxrwxrwx. 1 user user 0 Jan 27 11:48 uts -> uts:[4026531838]
[user@localhost ~]$ docker exec -it f52 sh
/ # ps
PID   USER     TIME  COMMAND
    1 root      0:00 sleep 9999
   11 root      0:00 sh
   16 root      0:00 ps
/ # ls -al /proc/11/ns
total 0
dr-x--x--x    2 root     root             0 Jan 27 10:49 .
dr-xr-xr-x    9 root     root             0 Jan 27 10:49 ..
lrwxrwxrwx    1 root     root             0 Jan 27 10:49 ipc -> ipc:[4026532108]
lrwxrwxrwx    1 root     root             0 Jan 27 10:49 mnt -> mnt:[4026532106]
lrwxrwxrwx    1 root     root             0 Jan 27 10:49 net -> net:[4026532111]
lrwxrwxrwx    1 root     root             0 Jan 27 10:49 pid -> pid:[4026532109]
lrwxrwxrwx    1 root     root             0 Jan 27 10:49 user -> user:[4026531837]
lrwxrwxrwx    1 root     root             0 Jan 27 10:49 uts -> uts:[4026532107]
```

### D. `nsenter`

🌞 Utiliser `nsenter` pour rentrer dans les namespaces de votre conteneur en y exécutant un shell

- prouver que vous êtes isolé en terme de réseau, arborescence de processus, points de montage

```shell=

```

### E. Et alors, les namespaces User

🌞 Mettez en place la configuration nécessaire pour que Docker utilise les namespaces de type User.

```shell=

```

### F. Isolation réseau

Observer les opérations liées au réseau lors de l'exécution d'un conteneur

- 🌞 lancer un conteneur simple
  - je vous conseille une image `debian` histoire d'avoir des commandes comme `ip a` qui n'existent pas dans une image allégée comme `alpine`)
  - ajouter une option pour partager un port (n'importe lequel), pour voir plus d'informations
    - `docker run -d -p 8888:7777 debian sleep 99999`

```shell=
docker run -d -p 8888:7777 debian sleep 99999
```

- 🌞 vérifier le réseau du conteneur
  - vérifier que le conteneur a bien une carte réseau et repérer son IP
    - c'est une des interfaces de la *veth pair*
  - possible avec un shell dans le conteneur OU avec un `docker inspect` depuis l'hôte

```shell=
$ docker inspect 163 | grep "IPAddress"
            "SecondaryIPAddresses": null,
            "IPAddress": "172.18.0.3",
                    "IPAddress": "172.18.0.3",
```

- 🌞 vérifier le réseau sur l'hôte
  - vérifier qu'il existe une première carte réseau qui porte une IP dans le même réseau que le conteneur
  - vérifier qu'il existe une deuxième carte réseau, qui est la deuxième interface de la *veth pair*
    - son nom ressemble à *vethXXXXX@ifXX*
  - identifier les règles *iptables* liées à la création de votre conteneur  

```shell=
$ ip a | grep -e "docker0" -e "veth"
4: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    inet 172.18.0.1/16 brd 172.18.255.255 scope global docker0
14: veth5e9a464@if13: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default
$
$
$ sudo iptables -L | grep -B 2 "172.18.0.3"
Chain DOCKER (1 references)
target     prot opt source               destination
ACCEPT     tcp  --  anywhere             172.18.0.3           tcp dpt:cbt
```

## 2. Cgroups

### A. Découverte manuelle

🌞 Lancer un conteneur Docker et déduire dans quel cgroup il s'exécute

```shell=
$ systemd-cgtop
Path                                                                                                                                                                                                  Tasks   %CPU   Memory  Input/s Output/s
/docker/5f26b41a31c7686a0801128ecea96376a8ed68d8963a957d8bd7c8e13cb9bac2                                                                                                                                  1      -    16.6M        -        -
```

### B. Utilisation par Docker

🌞 Lancer un conteneur Docker et trouver

- la mémoire RAM max qui lui est autorisée
- le nombre de processus qu'il peut contenir
- explorer un peu de vous-même ce qu'il est possible de faire avec des cgroups  

```shell=
$ cat /sys/fs/cgroup/memory/docker/79fa961246d31f3afa16292550908edd905e5d41b821f5c3d738b6454e45bce5/memory.limit_in_bytes
9223372036854771712
$
$
$ cat /sys/fs/cgroup/cpu/docker/79fa961246d31f3afa16292550908edd905e5d41b821f5c3d738b6454e45bce5/cpuacct.usage_percpu
22676576
```

🌞 Altérer les valeurs cgroups allouées par défaut avec des options de la commandes `docker run` (au moins 3)

- préciser les options utilisées
- prouver en regardant dans `/sys` qu'elles sont utilisées

```shell=
$ docker run -d -c 4 --memory 4096m --pids-limit 5 b5d sleep 99999999
$
$
$ cat /sys/fs/cgroup/pids/docker/6cfd3d2f037d7e15643b81b99523563c46eac2c7d75a372bb9d79e108c676a4a/pids.max
5
$
$
$ cat /sys/fs/cgroup/memory/docker/6cfd3d2f037d7e15643b81b99523563c46eac2c7d75a372bb9d79e108c676a4a/memory.limit_in_bytes
4294967296
$
$
$ cat /sys/fs/cgroup/cpu/docker/6cfd3d2f037d7e15643b81b99523563c46eac2c7d75a372bb9d79e108c676a4a/cpuacct.usage_percpu
24277850
```

> docker run -d -c 4 --memory 4096m --pids-limit 5 b5d sleep 99999999

```shell=
$ docker run --help | grep -e "-c," -e "--memory bytes" -e "--pids-limit"
  -c, --cpu-shares int                 CPU shares (relative weight)
  -m, --memory bytes                   Memory limit
      --pids-limit int                 Tune container pids limit (set -1 for unlimited)
```

## 3. Capabilities

### A.  Découverte manuelle

Utiliser `capsh --print`

- cela affiche des informations avancées sur votre shell
- 🌞 déterminer les capabilities actuellement utilisées par votre shell

```shell=
$ capsh --print
Current: =
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,35,36
```

---

🌞 Déterminer les capabilities du processus lancé par un conteneur Docker

- utiliser quelque chose de simple pour le conteneur comme un `docker run -d alpine sleep 99999`
- en utilisant `/proc`

```shell=
$ docker exec -it e2d ps
PID   USER     TIME  COMMAND
    1 root      0:00 sleep 99999
   16 root      0:00 ps
$
$
$ docker exec -it e2d cat /proc/1/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
```

---

🌞 Jouer avec `ping`

- trouver le chemin absolu de `ping`
- récupérer la liste de ses capabilities
- enlever toutes les capabilities
  - en utilisant une liste vide
  - `setcap '' <PATH>`
- vérifier que `ping` ne fonctionne plus
- vérifier avec `strace` que c'est bien l'accès à l'ICMP qui a été enlevé
  - NB : vous devrez aussi ajouter des capa à strace pour que son ping puisse en hériter !

```shell=
$ getcap /usr/bin/ping
/usr/bin/ping = cap_net_admin,cap_net_raw+p
$
$
$ sudo setcap -r /usr/bin/ping
$
$
$ ping 8.8.8.8
ping: socket: Operation not permitted
$
$
$ strace ping 8.8.8.8
[...]
socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) = -1 EPERM (Operation not permitted)
[...]
```

> N'oubliez pas de remettre ses capabilities à votre `ping` ;)

```shell=
$ sudo setcap cap_net_admin,cap_net_raw+p /usr/bin/ping
$
$ getcap /usr/bin/ping
/usr/bin/ping = cap_net_admin,cap_net_raw+p
$ ping 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
^C
--- 8.8.8.8 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 999ms
```

### B.  Utilisation par Docker

🌞 lancer un conteneur NGINX qui a le strict nécessaire de capabilities pour fonctionner

- prouver qu'il fonctionne
- expliquer toutes les capabilities dont il a besoin

```shell=
$ docker run -d -p 80:80 --cap-drop=all --cap-add=chown --cap-add=setgid --cap-add=setuid --cap-add=net_bind_service nginx
$
$
$ curl localhost | head -4
[...]
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
```

Capabilities :

> - chown :
>   - Apporte des modifications arbitraires aux fichiers des UID et GID
> - setgid :
>   - Effectue des manipulations arbitraire des processus d'un GID et d'une liste de GID supplémenaire
>   - falsifier le GID lors du passage des informations d'identification de socket via les sockets de domaine UNIX
>   - Ecrit un ID de groupe dans un espace de nom utilisateur
> - setuid :
>   - Effectue des manipulations arbitraire des processus d'un UID
>   - falsifier l'UID lors du passage des informations d'identification de socket via les sockets de domaine UNIX
>   - Ecrit un ID utilisateur dans un espace de nom utilisateur
> - net_bind_service :
>   - Lier un socket  à un port privilégiés du domaine Internet (en dessous du port 1024)

Enjoy :tada:
