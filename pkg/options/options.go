package options

import "github.com/spf13/pflag"

type NetdConfig struct {
	EnablePolicyRouting bool
	EnableMasquerade    bool
}

func NewNetdConfig() *NetdConfig {
	return &NetdConfig{}
}

func (nc *NetdConfig) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&nc.EnablePolicyRouting, "enable-policy-routing", true,
		"Enable policy routing.")
	fs.BoolVar(&nc.EnableMasquerade, "enable-masquerade", true,
		"Enable masquerade.")
}
