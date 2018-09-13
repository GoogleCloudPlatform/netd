# netd

netd is a Daemon designed to provide networking related features on GCP.
The initial version is to generate CNI Spec for PTP plugin based on PodCIDR
from Kubernetes API server.

## Releases
Please refer to [netd/RELEASE.md](https://github.com/GoogleCloudPlatform/netd/blob/master/RELEASE.md).

## Deployment

netd is deployed at [cluster/addons/netd](https://github.com/kubernetes/kubernetes/tree/master/cluster/addons/netd),
it's guarded by KUBE_ENABLE_NETD.
