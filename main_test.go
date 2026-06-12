package main

import (
	"net"
	"strings"
	"testing"
)

func TestParsePortFilterAcceptsListsAndRanges(t *testing.T) {
	filter, err := parsePortFilter("80,443,5000-5002")
	if err != nil {
		t.Fatalf("parsePortFilter returned error: %v", err)
	}

	for _, port := range []int{80, 443, 5000, 5001, 5002} {
		if !filter.Contains(port) {
			t.Fatalf("expected port %d to be accepted", port)
		}
	}

	for _, port := range []int{22, 4999, 5003} {
		if filter.Contains(port) {
			t.Fatalf("expected port %d to be rejected", port)
		}
	}
}

func TestParsePortFilterRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{"", "0", "65536", "5000-4999", "abc"} {
		if _, err := parsePortFilter(input); err == nil {
			t.Fatalf("expected %q to be invalid", input)
		}
	}
}

func TestDNSRecordsAggregateIntoFilteredMDNSAsset(t *testing.T) {
	packet := dnsPacket(
		rrPTR("_http._tcp.local", "slw-nas._http._tcp.local", 10),
		rrSRV("slw-nas._http._tcp.local", 5000, "slw-nas.local", 10),
		rrTXT("slw-nas._http._tcp.local", []string{"path=/", "model=TS-X64"}, 10),
		rrA("slw-nas.local", net.IPv4(192, 168, 1, 10), 10),
		rrAAAA("slw-nas.local", net.ParseIP("fe80::265e:beff:fe69:a313"), 10),
	)

	records, err := decodeDNSMessage(packet)
	if err != nil {
		t.Fatalf("decodeDNSMessage returned error: %v", err)
	}

	_, ipNet, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	ports, err := parsePortFilter("5000")
	if err != nil {
		t.Fatal(err)
	}

	result := aggregateResult(records, ipNet, ports)
	if len(result.Services) != 1 {
		t.Fatalf("expected 1 service, got %d: %#v", len(result.Services), result.Services)
	}

	service := result.Services[0]
	if service.IP != "192.168.1.10" {
		t.Fatalf("unexpected IPv4: %q", service.IP)
	}
	if service.IPv6 != "fe80::265e:beff:fe69:a313" {
		t.Fatalf("unexpected IPv6: %q", service.IPv6)
	}
	if service.Port != 5000 || service.Proto != "tcp" || service.Service != "http" {
		t.Fatalf("unexpected service identity: %#v", service)
	}
	if service.Name != "slw-nas" || service.Hostname != "slw-nas.local" {
		t.Fatalf("unexpected host identity: %#v", service)
	}
	if service.TTL != 10 {
		t.Fatalf("unexpected TTL: %d", service.TTL)
	}
	if service.Banner["path"] != "/" || service.Banner["model"] != "TS-X64" {
		t.Fatalf("unexpected banner fields: %#v", service.Banner)
	}
	if len(result.Answers.PTR) != 1 || result.Answers.PTR[0] != "_http._tcp.local" {
		t.Fatalf("unexpected PTR answers: %#v", result.Answers.PTR)
	}
}

func TestFormatTextIncludesDeepBannerAndPTRAnswers(t *testing.T) {
	result := ScanResult{
		Services: []Asset{
			{
				IP:       "192.168.1.10",
				IPv6:     "fe80::265e:beff:fe69:a313",
				Port:     5000,
				Proto:    "tcp",
				Service:  "qdiscover",
				Name:     "slw-nas",
				Hostname: "slw-nas.local",
				TTL:      10,
				Banner: map[string]string{
					"accessType":   "https",
					"accessPort":   "86",
					"model":        "TS-X64",
					"displayModel": "TS-464C",
					"fwVer":        "5.2.9",
					"fwBuildNum":   "20260214",
				},
				BannerRaw: []string{"accessType=https", "accessPort=86", "model=TS-X64", "displayModel=TS-464C", "fwVer=5.2.9", "fwBuildNum=20260214"},
			},
		},
		Answers: Answers{PTR: []string{"_qdiscover._tcp.local"}},
	}

	output := formatText(result)
	for _, want := range []string{
		"services:",
		"5000/tcp qdiscover:",
		"Name=slw-nas",
		"IPv4=192.168.1.10",
		"Hostname=slw-nas.local",
		"accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214",
		"answers:",
		"_qdiscover._tcp.local",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, output)
		}
	}
}

type testRR []byte

// 以下测试辅助函数手工构造 DNS 响应包，避免单元测试依赖真实局域网设备。
func dnsPacket(records ...testRR) []byte {
	packet := []byte{
		0x00, 0x00,
		0x84, 0x00,
		0x00, 0x00,
		byte(len(records) >> 8), byte(len(records)),
		0x00, 0x00,
		0x00, 0x00,
	}
	for _, record := range records {
		packet = append(packet, record...)
	}
	return packet
}

func rrPTR(name, target string, ttl uint32) testRR {
	return rr(name, dnsTypePTR, ttl, encodeName(target))
}

func rrSRV(name string, port uint16, target string, ttl uint32) testRR {
	rdata := []byte{0x00, 0x00, 0x00, 0x00, byte(port >> 8), byte(port)}
	rdata = append(rdata, encodeName(target)...)
	return rr(name, dnsTypeSRV, ttl, rdata)
}

func rrTXT(name string, values []string, ttl uint32) testRR {
	var rdata []byte
	for _, value := range values {
		rdata = append(rdata, byte(len(value)))
		rdata = append(rdata, []byte(value)...)
	}
	return rr(name, dnsTypeTXT, ttl, rdata)
}

func rrA(name string, ip net.IP, ttl uint32) testRR {
	return rr(name, dnsTypeA, ttl, ip.To4())
}

func rrAAAA(name string, ip net.IP, ttl uint32) testRR {
	return rr(name, dnsTypeAAAA, ttl, ip.To16())
}

func rr(name string, typ uint16, ttl uint32, rdata []byte) testRR {
	record := encodeName(name)
	record = append(record,
		byte(typ>>8), byte(typ),
		0x00, 0x01,
		byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl),
		byte(len(rdata)>>8), byte(len(rdata)),
	)
	record = append(record, rdata...)
	return record
}

func encodeName(name string) []byte {
	parts := strings.Split(strings.TrimSuffix(name, "."), ".")
	var out []byte
	for _, part := range parts {
		out = append(out, byte(len(part)))
		out = append(out, []byte(part)...)
	}
	return append(out, 0x00)
}
