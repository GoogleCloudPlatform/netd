package netconf

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/netd/pkg/config"

	"k8s.io/apimachinery/pkg/util/version"
)

func TestNewNetworkConfigController(t *testing.T) {
	originalGetKernelVersion := GetKernelVersion
	defer func() {
		GetKernelVersion = originalGetKernelVersion
	}()

	allEnabledConfigs := []config.Config{config.SourceValidMarkConfig}
	allEnabledConfigs = append(allEnabledConfigs, config.ExcludeDNSIPRuleConfigs...)
	allEnabledConfigs = append(allEnabledConfigs, config.ExcludeUDPIPRuleConfig)

	testCases := []struct {
		desc                  string
		enablePolicyRouting   bool
		enableSourceValidMark bool
		excludeDNS            bool
		kernelVersion         string
		kernelErr             error
		wantEnabled           bool
		wantConfigs           []config.Config
	}{
		{
			desc:        "all disabled, kernel error",
			kernelErr:   errors.New("kernel version error"),
			wantEnabled: false,
			wantConfigs: []config.Config{},
		},
		{
			desc:                "policy routing enabled",
			enablePolicyRouting: true,
			kernelVersion:       "5.0.0",
			wantEnabled:         true,
			wantConfigs:         []config.Config{},
		},
		{
			desc:                  "source valid mark enabled",
			enableSourceValidMark: true,
			kernelVersion:         "5.0.0",
			wantEnabled:           false,
			wantConfigs:           []config.Config{config.SourceValidMarkConfig},
		},
		{
			desc:          "exclude DNS enabled",
			excludeDNS:    true,
			kernelVersion: "5.0.0",
			wantEnabled:   false,
			wantConfigs:   config.ExcludeDNSIPRuleConfigs,
		},
		{
			desc:          "low kernel version",
			kernelVersion: "6.6.56",
			wantEnabled:   false,
			wantConfigs:   []config.Config{},
		},
		{
			desc:          "impacted kernel version",
			kernelVersion: "6.6.57",
			wantEnabled:   false,
			wantConfigs:   []config.Config{config.ExcludeUDPIPRuleConfig},
		},
		{
			desc:          "higher impacted kernel version",
			kernelVersion: "6.7.0",
			wantEnabled:   false,
			wantConfigs:   []config.Config{config.ExcludeUDPIPRuleConfig},
		},
		{
			desc:                  "all enabled with impacted kernel",
			enablePolicyRouting:   true,
			enableSourceValidMark: true,
			excludeDNS:            true,
			kernelVersion:         "6.6.57",
			wantEnabled:           true,
			wantConfigs:           allEnabledConfigs,
		},
	}

	for _, tc := range testCases {
		config.PolicyRoutingConfigSet.Configs = nil
		config.PolicyRoutingConfigSet.Enabled = false
		t.Run(tc.desc, func(t *testing.T) {
			GetKernelVersion = func() (*version.Version, error) {
				if tc.kernelErr != nil {
					return nil, tc.kernelErr
				}
				return version.MustParseGeneric(tc.kernelVersion), nil
			}

			reconcileInterval := 10 * time.Second
			controller := NewNetworkConfigController(tc.enablePolicyRouting, tc.enableSourceValidMark, tc.excludeDNS, reconcileInterval)

			if controller.reconcileInterval != reconcileInterval {
				t.Errorf("controller.reconcileInterval = %v, want %v", controller.reconcileInterval, reconcileInterval)
			}

			if len(controller.configSet) != 1 {
				t.Fatalf("len(controller.configSet) = %d, want 1", len(controller.configSet))
			}

			cs := controller.configSet[0]
			if cs.Enabled != tc.wantEnabled {
				t.Errorf("cs.Enabled = %v, want %v", cs.Enabled, tc.wantEnabled)
			}

			if !configsEqual(cs.Configs, tc.wantConfigs) {
				t.Errorf("cs.Configs = %+v, want %+v", cs.Configs, tc.wantConfigs)
			}
		})
	}
}

func configsEqual(a, b []config.Config) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if reflect.TypeOf(a[i]) != reflect.TypeOf(b[i]) {
			return false
		}

		switch ta := a[i].(type) {
		case config.SysctlConfig:
			tb := b[i].(config.SysctlConfig)
			if ta.Key != tb.Key || ta.Value != tb.Value || ta.DefaultValue != tb.DefaultValue {
				return false
			}
		case config.IPRuleConfig:
			tb := b[i].(config.IPRuleConfig)
			if !reflect.DeepEqual(ta.Rule, tb.Rule) {
				return false
			}
		default:
			if !reflect.DeepEqual(a[i], b[i]) {
				return false
			}
		}
	}
	return true
}
