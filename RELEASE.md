# netd releases

## 0.1.7 [backlog]
### Features
### Bug fixs

## 0.1.6
### Features
 * Add support for generating a Calico CNI Spec.
 * Update netd DaemonSet's updateStrategy to be RollingUpdate and tolerations.
 * Make reconcile interval configurable.
 * Ensure configurations once the controller loop started.
 * Version and config logging.
 * change nodeSelector label to gke instead of k8s
 * update the addonmanager mode to Reconcile
### Bug fixs
 * Update dependency.

## 0.1 - 0.1.5
### Features
 * Multi-Container Architecture, use init container for spec generation.
 * netd infrastructure.
 * Deploy PTP CNI spec.
 * Configure pods with an additional IPv6 address if Direct Path is enabled.
 * Reconcile policy routing implemented by ip, iptables rules and sysctl settings.