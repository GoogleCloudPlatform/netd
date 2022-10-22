package collector

import (
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	return c.now
}

func (c *fakeClock) Sleep(d time.Duration) {
	c.now = c.now.Add(d)
}

func mustCreateFile(t *testing.T, dir, name, content string) {
	path := dir + "/" + name
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Error creating file path %s: %v", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("Error writing to file %s: %v", path, err)
	}
}

func mustDeleteFile(t *testing.T, dir, name string) {
	path := dir + "/" + name
	if err := os.Remove(path); err != nil {
		t.Fatalf("Error removing file path %s: %v", path, err)
	}
}

func mustCreateIPAddrDir(t *testing.T, dir string) string {
	tempDir, err := os.MkdirTemp("", dir)
	if err != nil {
		t.Fatalf("Error creating dir %s: %v", dir, err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	mustCreateFile(t, tempDir, "lock", "")
	mustCreateFile(t, tempDir, "last_allocated_ip.0", "10.0.0.1")
	return tempDir
}

func TestListIpAddresses(t *testing.T) {
	// dir1 has 2 IPv4 addresses and 2 IPv6 addresses for dual stack pods
	dir1 := mustCreateIPAddrDir(t, "dir1")
	mustCreateFile(t, dir1, "10.0.0.1", "hash1")
	mustCreateFile(t, dir1, "10.0.0.2", "hash2")
	mustCreateFile(t, dir1, "2600:1900::1", "hash1")
	mustCreateFile(t, dir1, "2600:1900::2", "hash2")

	// dir2 has 2 IPv4 addresses and 2 IPv6 addresses but only one real dual stack
	// pod
	dir2 := mustCreateIPAddrDir(t, "dir2")
	mustCreateFile(t, dir2, "10.0.0.1", "hash1")
	mustCreateFile(t, dir2, "10.0.0.2", "hash2")
	mustCreateFile(t, dir2, "2600:1900::1", "hash1")
	mustCreateFile(t, dir2, "2600:1900::3", "hash3")

	// dir3 has 2 IPv4 and IPv6 addresses allocated for the same pod
	dir3 := mustCreateIPAddrDir(t, "dir3")
	mustCreateFile(t, dir3, "10.0.0.1", "hash1")
	mustCreateFile(t, dir3, "10.0.0.2", "hash1")
	mustCreateFile(t, dir3, "2600:1900::1", "hash1")
	mustCreateFile(t, dir3, "2600:1900::2", "hash1")

	for _, tc := range []struct {
		desc                  string
		dir                   string
		stackType             string
		wantUsedIPv4Count     uint64
		wantUsedIPv6Count     uint64
		wantDualStackCount    uint64
		wantDualStackErrCount uint64
		wantDuplicateIPCount  uint64
		wantErr               bool
	}{
		{
			desc:      "bad directory",
			dir:       "bogus",
			stackType: "IPV4",
			wantErr:   true,
		},
		{
			desc:              "dir1 with 2 IPv4 and 2 IPv6 addresses. Single stack",
			dir:               dir1,
			stackType:         "IPV4",
			wantUsedIPv4Count: 2,
			wantUsedIPv6Count: 2,
		},
		{
			desc:               "dir1 with 2 IPv4 and 2 IPv6 addresses. dual stack",
			dir:                dir1,
			stackType:          "IPV4_IPV6",
			wantUsedIPv4Count:  2,
			wantUsedIPv6Count:  2,
			wantDualStackCount: 2,
		},
		{
			desc:                  "dir2 with dual stack errors",
			dir:                   dir2,
			stackType:             "IPV4_IPV6",
			wantUsedIPv4Count:     2,
			wantUsedIPv6Count:     2,
			wantDualStackCount:    1,
			wantDualStackErrCount: 2,
		},
		{
			desc:                 "dir2 with dual stack and dup IPs",
			dir:                  dir3,
			stackType:            "IPV4_IPV6",
			wantUsedIPv4Count:    2,
			wantUsedIPv6Count:    2,
			wantDualStackCount:   1,
			wantDuplicateIPCount: 2,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			stackType = tc.stackType
			mc := podIPMetricsCollector{}
			err := mc.listIPAddresses(tc.dir)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("Expected error %t, got error: %v", tc.wantErr, err)
				return
			}
			if mc.usedIPv4AddrCount != tc.wantUsedIPv4Count {
				t.Errorf("usedIpv4AddrCount. want: %d, got %d", tc.wantUsedIPv4Count, mc.usedIPv4AddrCount)
			}
			if mc.usedIPv6AddrCount != tc.wantUsedIPv6Count {
				t.Errorf("usedIpv6AddrCount. want: %d, got %d", tc.wantUsedIPv6Count, mc.usedIPv6AddrCount)
			}
			if mc.dualStackCount != tc.wantDualStackCount {
				t.Errorf("dualStackCount. want: %d, got %d", tc.wantDualStackCount, mc.dualStackCount)
			}
			if mc.dualStackErrorCount != tc.wantDualStackErrCount {
				t.Errorf("dualStackErrorCount. want: %d, got %d", tc.wantDualStackErrCount, mc.dualStackErrorCount)
			}
			if mc.duplicateIPCount != tc.wantDuplicateIPCount {
				t.Errorf("duplicateIpCount. want: %d, got %d", tc.wantDuplicateIPCount, mc.duplicateIPCount)
			}
		})
	}
}

func TestSetupDirectoryWatcher(t *testing.T) {
	// dir1 has 2 IPv4 addresses and 2 IPv6 addresses for dual stack pods
	dir1 := mustCreateIPAddrDir(t, "dir1")
	mustCreateFile(t, dir1, "10.0.0.1", "hash1")
	mustCreateFile(t, dir1, "10.0.0.2", "hash2")
	mustCreateFile(t, dir1, "2600:1900::1", "hash1")
	mustCreateFile(t, dir1, "2600:1900::2", "hash2")
	stackType = "IPV4_IPV6"

	// Setup directory watcher and verify metrics
	fakeClock := &fakeClock{}
	mc := podIPMetricsCollector{clock: fakeClock}
	bucketKeys := prometheus.LinearBuckets(5e3, 5e3, 12)
	if err := mc.setupDirectoryWatcher(dir1); err != nil {
		t.Fatalf("Got error %v while setting up directory watcher", err)
	}
	if mc.usedIPv4AddrCount != 2 {
		t.Errorf("usedIpv4AddrCount. want: 2, got %d", mc.usedIPv4AddrCount)
	}
	if mc.usedIPv6AddrCount != 2 {
		t.Errorf("usedIpv6AddrCount. want: 2, got %d", mc.usedIPv6AddrCount)
	}
	if mc.dualStackCount != 2 {
		t.Errorf("dualStackCount. want: 2, got %d", mc.dualStackCount)
	}
	if mc.dualStackErrorCount != 0 {
		t.Errorf("dualStackErrorCount. want: 0, got %d", mc.dualStackErrorCount)
	}
	if mc.duplicateIPCount != 0 {
		t.Errorf("duplicateIpCount. want: 0, got %d", mc.duplicateIPCount)
	}
	for _, bound := range bucketKeys {
		v, ok := mc.reuseIPs.buckets[bound]
		if !ok {
			t.Errorf("buckets are initialized with 0 values. want: ok, got %v", ok)
		} else if v != 0 {
			t.Errorf("no file is deleted. want value to be 0, got %v", v)
		}
	}
	if !podIPMetricsWatcherSetup {
		t.Fatal("podIpMetricsWatcherSetup: want: true, got: false")
	}

	//Add a new file to the directory. Verify metrics
	mustCreateFile(t, dir1, "10.0.0.3", "hash3")
	time.Sleep(1 * time.Second)
	if mc.usedIPv4AddrCount != 3 {
		t.Errorf("usedIpv4AddrCount. want: 3, got %d", mc.usedIPv4AddrCount)
	}
	if mc.usedIPv6AddrCount != 2 {
		t.Errorf("usedIpv6AddrCount. want: 2, got %d", mc.usedIPv6AddrCount)
	}
	if mc.dualStackCount != 2 {
		t.Errorf("dualStackCount. want: 2, got %d", mc.dualStackCount)
	}
	if mc.dualStackErrorCount != 1 {
		t.Errorf("dualStackErrorCount. want: 1, got %d", mc.dualStackErrorCount)
	}
	if mc.duplicateIPCount != 0 {
		t.Errorf("duplicateIpCount. want: 0, got %d", mc.duplicateIPCount)
	}

	//Remove a file from the directory. Verify metrics
	mustDeleteFile(t, dir1, "10.0.0.3")
	time.Sleep(1 * time.Second)
	if mc.usedIPv4AddrCount != 2 {
		t.Errorf("usedIpv4AddrCount. want: 2, got %d", mc.usedIPv4AddrCount)
	}
	if mc.usedIPv6AddrCount != 2 {
		t.Errorf("usedIpv6AddrCount. want: 2, got %d", mc.usedIPv6AddrCount)
	}
	if mc.dualStackCount != 2 {
		t.Errorf("dualStackCount. want: 2, got %d", mc.dualStackCount)
	}
	if mc.dualStackErrorCount != 0 {
		t.Errorf("dualStackErrorCount. want: 0, got %d", mc.dualStackErrorCount)
	}
	if mc.duplicateIPCount != 0 {
		t.Errorf("duplicateIpCount. want: 0, got %d", mc.duplicateIPCount)
	}

	// Remove and recreate the file. Verify metrics
	fakeClock.Sleep(6 * time.Second)
	mustDeleteFile(t, dir1, "10.0.0.2")
	mustDeleteFile(t, dir1, "lock")
	mustDeleteFile(t, dir1, "2600:1900::1")
	time.Sleep(1 * time.Second)

	mustCreateFile(t, dir1, "10.0.0.3", "hash3")
	fakeClock.Sleep(5 * time.Second)
	mustCreateFile(t, dir1, "10.0.0.2", "hash2")
	mustCreateFile(t, dir1, "lock", "")
	mustCreateFile(t, dir1, "2600:1900::1", "hash1")
	time.Sleep(1 * time.Second)

	for _, bound := range bucketKeys {
		v, ok := mc.reuseIPs.buckets[bound]
		if !ok {
			t.Errorf("reused ip: buckets are initialized with 0 values. want: ok, got %v", ok)
		} else if bound == 5e3 && v != 0 {
			t.Errorf("reused ip: bucket with le==5. want: 0, got %d", v)
		} else if bound == 10e3 && v != 1 {
			// 10.0.0.3 is reused in 6 seconds
			t.Errorf("reused ip: bucket with le==10. want: 1, got %d", v)
		} else if bound >= 15e3 && v != 2 {
			// 10.0.0.2 is reused in 11 seconds, so included 10.0.0.3 for buckets: (10, 15] and (15, +Inf), sizes are 2
			// file "2600:1900::1" and "lock" are not counted in the bucket
			t.Errorf("reused ip: bucket with le>=15. want: 2, got %d", v)
		}
	}
}
