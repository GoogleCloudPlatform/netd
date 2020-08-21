module github.com/GoogleCloudPlatform/netd

go 1.14

require (
	github.com/containernetworking/cni v0.8.0
	github.com/containernetworking/plugins v0.7.3
	github.com/coreos/etcd v3.3.24+incompatible
	github.com/coreos/go-iptables v0.4.5
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf // indirect
	github.com/fsnotify/fsnotify v1.4.7
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/prometheus/client_golang v0.9.3
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	github.com/vishvananda/netlink v1.0.0
	github.com/vishvananda/netns v0.0.0-20180720170159-13995c7128cc // indirect
	golang.org/x/sys v0.0.0-20191022100944-742c48ecaeb7
	k8s.io/api v0.18.8
	k8s.io/apimachinery v0.18.8
	k8s.io/client-go v0.18.8
	k8s.io/utils v0.0.0-20200815180417-3bc9d57fc792 // indirect
)
