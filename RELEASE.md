# netd releases

## 0.2.10
### Features
 * Add support to handle GKE ENABLE_IPV6 flag and populate ipv6Subnet

## 0.2.9
### Features
 * network metrics - Collect nf_conntrack_max value

## 0.2.8
### Features
 * Write the generated CNI files atomically
 * Update to use golang 1.14
### Bug fixes
 * ReconcileInterval is now correctly set to 10s
 * Only wait for the Calico CNI spec if not generating the calico template file

## 0.2.7
### Features
 * Support Cilium plugin.

## 0.2.6
### Bug fixs
 * Overide calico network policy config if it didn't install CNI

## 0.2.5
### Features
 * bandwidth plugin support.

## 0.2.4
### Features
 * Read the mtu from default nic.
### Bug fixs
 * Install the ip6tables package in the init container along with iptables.
 * Add PodCidr validation.

## 0.2.2
### Features
### Bug fixs
 * Limit rp filter loose config only to eth0 interface
 * netd should not reconciling ip-masq rules
 * Makefile updates

## 0.2.1
### Features
### Bug fixs
 * Add some required IPv6 firewall rules when IPv6 support is enabled
 * GKE CNI support
 * Remove unused config: noSnat for portMap

## 0.2.0
### Features
 * Add network metrics collection
### Bug fixs
 * Fix golint errors

## 0.1.9
### Features
### Bug fixs
 * Reduce Calico CNI's log_level from debug to info, Add MTU=1460 for Calico CNI on GCP
 * Remove version info from init container script.
 * Remove calico_cni_spec_template from netd yaml
 * Enable IPv6 forwarding when Calico CNI is used.

## 0.1.8 [backlog]
### Bug fixs
 * fix reconcile and ipmasq chain bug
 * update comments

## 0.1.7
### Bug fixs
 * Quick fix to avoid unnecessary CNI spec generation. PR#44

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
