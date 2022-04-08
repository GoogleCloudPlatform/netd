package collector

import (
	"io/ioutil"
	"os"
	"testing"
)

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

func mustCreateIpAddrDir(t *testing.T, dir string) string {
	tempDir, err := ioutil.TempDir("", dir)
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
	dir1 := mustCreateIpAddrDir(t, "dir1")
	mustCreateFile(t, dir1, "10.0.0.1", "hash1")
	mustCreateFile(t, dir1, "10.0.0.2", "hash2")
	mustCreateFile(t, dir1, "2600:1900::1", "hash1")
	mustCreateFile(t, dir1, "2600:1900::2", "hash2")

	// dir2 has 2 IPv4 addresses and 2 IPv6 addresses but only one real dual stack
	// pod
	dir2 := mustCreateIpAddrDir(t, "dir2")
	mustCreateFile(t, dir2, "10.0.0.1", "hash1")
	mustCreateFile(t, dir2, "10.0.0.2", "hash2")
	mustCreateFile(t, dir2, "2600:1900::1", "hash1")
	mustCreateFile(t, dir2, "2600:1900::3", "hash3")

	// dir3 has 2 IPv4 and IPv6 addresses allocated for the same pod
	dir3 := mustCreateIpAddrDir(t, "dir3")
	mustCreateFile(t, dir3, "10.0.0.1", "hash1")
	mustCreateFile(t, dir3, "10.0.0.2", "hash1")
	mustCreateFile(t, dir3, "2600:1900::1", "hash1")
	mustCreateFile(t, dir3, "2600:1900::2", "hash1")

	for _, tc := range []struct {
		desc string
		dir string
		stackType string
		wantUsedIpv4Count uint64
		wantUsedIpv6Count uint64
		wantDualStackCount uint64
		wantDualStackErrCount uint64
		wantDuplicateIpCount uint64
		wantErr bool
	} {
		{
			desc: "bad directory",
			dir: "bogus",
			stackType: "IPV4",
			wantErr: true,
		},
		{
			desc: "dir1 with 2 IPv4 and 2 IPv6 addresses. Single stack",
			dir: dir1,
			stackType: "IPV4",
			wantUsedIpv4Count: 2,
			wantUsedIpv6Count: 2,
		},
		{
			desc: "dir1 with 2 IPv4 and 2 IPv6 addresses. dual stack",
			dir: dir1,
			stackType: "IPV4_IPV6",
			wantUsedIpv4Count: 2,
			wantUsedIpv6Count: 2,
			wantDualStackCount: 2,
		},
		{
			desc: "dir2 with dual stack errors",
			dir: dir2,
			stackType: "IPV4_IPV6",
			wantUsedIpv4Count: 2,
			wantUsedIpv6Count: 2,
			wantDualStackCount: 1,
			wantDualStackErrCount: 2,
		},
		{
			desc: "dir2 with dual stack and dup IPs",
			dir: dir3,
			stackType: "IPV4_IPV6",
			wantUsedIpv4Count: 2,
			wantUsedIpv6Count: 2,
			wantDualStackCount: 1,
			wantDuplicateIpCount: 2,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			stackType = tc.stackType
			mc := podIpMetricsCollector{}
			err := mc.listIpAddresses(tc.dir)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("Expected error %t, got error: %v", tc.wantErr, err)
				return
			}
			if mc.usedIpv4AddrCount != tc.wantUsedIpv4Count {
				t.Errorf("usedIpv4AddrCount. want: %d, got %d", tc.wantUsedIpv4Count, mc.usedIpv4AddrCount)
			}
			if mc.usedIpv6AddrCount != tc.wantUsedIpv6Count {
				t.Errorf("usedIpv6AddrCount. want: %d, got %d", tc.wantUsedIpv6Count, mc.usedIpv6AddrCount)
			}
			if mc.dualStackCount != tc.wantDualStackCount {
				t.Errorf("dualStackCount. want: %d, got %d", tc.wantDualStackCount, mc.dualStackCount)
			}
			if mc.dualStackErrorCount != tc.wantDualStackErrCount {
				t.Errorf("dualStackErrorCount. want: %d, got %d", tc.wantDualStackErrCount, mc.dualStackErrorCount)
			}
			if mc.duplicateIpCount != tc.wantDuplicateIpCount {
				t.Errorf("duplicateIpCount. want: %d, got %d", tc.wantDuplicateIpCount, mc.duplicateIpCount)
			}
		})
	}
}
