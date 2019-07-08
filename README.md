# kube-iptables-tailer

[![Project Status](https://opensource.box.com/badges/active.svg)](https://opensource.box.com/badges)
[![Build Status](https://travis-ci.com/box/kube-iptables-tailer.svg?token=xQMR2mqCqLKhWA2AL639&branch=master)](https://travis-ci.com/box/kube-iptables-tailer)

kube-iptables-tailer is a service that gives you better visibility on networking issues in your Kubernetes cluster by detecting the traffic denied by iptables and surfacing corresponding information to the affected Pods via Kubernetes events.

kube-iptables-tailer itself runs as a Pod in your cluster, and it keeps watching changes on iptables log file [mounted from the host](#mounting-iptables-log-file). If traffic from/to a Pod is denied by your iptables rules, iptables will drop the packet and record a log entry on the host with relevant information. kube-iptables-tailer is able to detect these changes, and then it will try locating both the senders and receivers (as running Pods in your cluster) by their IPs. For IPs that do not match any Pods in your cluster, a DNS lookup will be performed to get subjects involved in the packet drops.

As the result, kube-iptables-tailer will submit an event in nearly real-time to the Pod located successfully inside your cluster. The Pod owners can thence be aware of iptables packet drops simply by running the following command:  

```shell
$ kubectl describe pods --namespace=YOUR_NAMESPACE

...
Events:
  FirstSeen   LastSeen    Count   From                    Type          Reason          Message
  ---------   --------	  -----	  ----                    ----          ------          -------
  1h          5s          10      kube-iptables-tailer    Warning       PacketDrop      Packet dropped when receiving traffic from example-service-2 (IP: 22.222.22.222).
  
  3h          2m          5       kube-iptables-tailer    Warning       PacketDrop      Packet dropped when sending traffic to example-service-1 (IP: 11.111.11.111).
```
**NOTE**: Content under the sections `From`, `Reason`, and `Message` showing in the above output can be configured in your container spec file. Please refer to the corresponding [environment variables](#environment-variables) below for a more detailed explanation.

## Requirements
* [Go (1.11+)](https://golang.org/dl/)
* [Docker (17.05+)](https://www.docker.com/get-started)
* [Kubernetes (1.11+)](https://kubernetes.io/docs/setup/)

## Installation

Download the source code package:
```shell
$ git clone github.com/box/kube-iptables-tailer
```

Build the container from the source code (make sure you have Docker running):
```shell
$ cd $GOPATH/src/github.com/box/kube-iptables-tailer
$ make container
```

## Usage 

### Setup iptables Log Prefix
kube-iptables-tailer uses log-prefix defined in your iptables chains to parse the corresponding packet dropped logs. You can set up the log-prefix by executing the following command (root permission might be required):    
```shell
$ iptables -A CHAIN_NAME -j LOG --log-prefix "EXAMPLE_LOG_PREFIX: "
```  

Any packets dropped by this chain will be logged containing the given log prefix:  
`2019-02-04T10:10:12.345678-07:00 hostname EXAMPLE_LOG_PREFIX: SRC=SOURCE_IP DST=DESTINATION_IP ...`  
For more information on iptables command, please refer to this [Linux man page](https://linux.die.net/man/8/iptables).

### Mounting iptables Log File
The parent **directory** of your iptables log file needs to be mounted for kube-iptables-tailer to handle log rotation properly. The service could not get updated content after the file is rotated if you only mount the log file. This is because files are mounted into the container with specific [inode](https://en.wikipedia.org/wiki/Inode) numbers, which remain the same even if the file names are changed on the host (usually happens after rotation).   
kube-iptables-tailer also applies a fingerprint for the current log file to handle log rotation as well as avoid reading the entire log file every time when its content get updated.

### Container Spec
We suggest running kube-iptables-tailer as a [Daemonset](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/) in your cluster. An example of YAML spec file can be found in [demo/](demo/).

### Environment Variables 

#### Required: 
* `IPTABLES_LOG_PATH` or `JOURNAL_DIRECTORY`: (string) Absolute path to your iptables log file, or journald directory including the full path. 
* `IPTABLES_LOG_PREFIX`: (string) Log prefix defined in your iptables chains. The service will only handle the logs matching this log prefix exactly.

#### Optional:
* `KUBE_API_SERVER`: (string) Address of the Kubernetes API server. By default, the discovery of the API server is handled by kube-proxy. If kube-proxy is not set up, the API server address must be specified with this environment variable. Authentication to the API server is handled by service account tokens. See [Accessing the Cluster](http://kubernetes.io/docs/user-guide/accessing-the-cluster/#accessing-the-api-from-a-pod) for more info.
* `KUBE_EVENT_DISPLAY_REASON`: (string, default: **PacketDrop**) A brief and UpperCamelCase formatted text showing under the [Reason](https://godoc.org/k8s.io/client-go/tools/record#EventRecorder) section in the event sent from this service.
* `KUBE_EVENT_SOURCE_COMPONENT_NAME`: (string, default: **kube-iptables-tailer**) A name showing under the From section to indicate the [source](https://godoc.org/k8s.io/api/core/v1#EventSource) of the Kubernetes event. 
* `METRICS_SERVER_PORT`: (int, default: **9090**) Port for the service to host its metrics.
* `PACKET_DROP_CHANNEL_BUFFER_SIZE`: (int, default: **100**) Size of the channel for existing items to handle. You may need to increase this value if you have a high rate of packet drops being recorded.
* `PACKET_DROP_EXPIRATION_MINUTES`: (int, default: **10**) Expiration of a packet drop in minutes. Any dropped packet log entries older than this duration will be ignored.
* `REPEATED_EVENTS_INTERVAL_MINUTES`: (int, default: **2**) Interval of ignoring repeated packet drops in minutes. Any dropped packet log entries with the same source and destination will be ignored if already submitted once within this time period. 
* `WATCH_LOGS_INTERVAL_SECONDS`: (int, default: **5**) Interval of detecting log changes in seconds. 
* `POD_IDENTIFIER`: (string, default: **namespace**) How to identify pods in the logs. `name`, `label` or `namespace` are currently supported. If `label`, uses the value of the label key specified by `POD_IDENTIFIER_LABEL`.
* `POD_IDENTIFIER_LABEL`: (string) Pod label key with which to identify pods if `POD_IDENTIFIER` is set to `label`. If this label doesn't exist on the pod, the pod name is used instead.

### Metrics 
Metrics are implemented by Prometheus, which are hosted on the web server at `/metrics`. The metrics have a name `packet_drops_count` and counter with the following tags:
* `src`: The namespace of sender Pod involved with a packet drop.
* `dst`: The namespace of receiver Pod involved with a packet drop.

### Logging
Logging is implemented using [glog](https://godoc.org/github.com/golang/glog). To change the output directory of logs, you can mount an [emptyDir](https://kubernetes.io/docs/concepts/storage/volumes/#emptydir) as a volume (where containers can have read and write access of the files inside) and add `--log_dir` as a command argument. Refer to [daemonset.yaml](demo/daemonset.yaml) provided as an example.

## Contribution
All contributions are welcome to this project! Please review our [contributing guidelines](CONTRIBUTING.md) to facilitate the process of your contribution getting mereged. 

## Support
Need to contact us directly? Email oss@box.com and be sure to include the name of this project in the subject.

## Copyright and License
Copyright 2019 Box, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
