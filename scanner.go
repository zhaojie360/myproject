package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

const mdnsIPv4Address = "224.0.0.251:5353"

// commonMDNSServiceTypes 先覆盖题目示例中的常见服务，再通过 _services 查询动态扩展。
var commonMDNSServiceTypes = []string{
	"_services._dns-sd._udp.local",
	"_workstation._tcp.local",
	"_http._tcp.local",
	"_smb._tcp.local",
	"_qdiscover._tcp.local",
	"_device-info._tcp.local",
	"_afpovertcp._tcp.local",
}

// scanMDNS 通过 IPv4 mDNS 组播发现服务；端口范围用于过滤 SRV 记录里的服务端口。
func scanMDNS(ctx context.Context, cfg scanConfig) (ScanResult, error) {
	addr, err := net.ResolveUDPAddr("udp4", mdnsIPv4Address)
	if err != nil {
		return ScanResult{}, err
	}

	var iface *net.Interface
	if cfg.interfaceName != "" {
		iface, err = net.InterfaceByName(cfg.interfaceName)
		if err != nil {
			return ScanResult{}, fmt.Errorf("interface %q not found: %w", cfg.interfaceName, err)
		}
	}

	// ListenMulticastUDP 会加入 224.0.0.251:5353，用于接收局域网设备的 mDNS 响应。
	conn, err := net.ListenMulticastUDP("udp4", iface, addr)
	if err != nil {
		return ScanResult{}, fmt.Errorf("listen mDNS multicast: %w", err)
	}
	defer conn.Close()

	if err := conn.SetReadBuffer(65535); err != nil {
		return ScanResult{}, fmt.Errorf("set read buffer: %w", err)
	}

	queries := map[string]struct{}{}
	for _, serviceType := range commonMDNSServiceTypes {
		queries[serviceType] = struct{}{}
	}

	// 先问一轮已知服务类型，后续如果发现新的 PTR 服务类型再补充查询。
	if err := sendMDNSQueries(conn, addr, queries, cfg.retries); err != nil {
		return ScanResult{}, err
	}

	var records []dnsRecord
	buffer := make([]byte, 65535)
	deadline := time.Now().Add(cfg.timeout)

	for {
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				break
			}
			return ScanResult{}, err
		}
		if time.Now().After(deadline) {
			break
		}

		readDeadline := time.Now().Add(250 * time.Millisecond)
		if readDeadline.After(deadline) {
			readDeadline = deadline
		}
		if err := conn.SetReadDeadline(readDeadline); err != nil {
			return ScanResult{}, err
		}

		// 单次短 read deadline 让循环能及时检查整体 timeout 和 context。
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return ScanResult{}, fmt.Errorf("read mDNS response: %w", err)
		}

		packetRecords, err := decodeDNSMessage(buffer[:n])
		if err != nil {
			continue
		}
		records = append(records, packetRecords...)

		// DNS-SD 的服务枚举结果可能返回更多服务类型，发现后立即追加 PTR 查询。
		discovered := discoveredServiceTypes(packetRecords)
		for _, serviceType := range discovered {
			if _, ok := queries[serviceType]; ok {
				continue
			}
			queries[serviceType] = struct{}{}
			if err := sendMDNSQuery(conn, addr, serviceType); err != nil {
				return ScanResult{}, err
			}
		}
	}

	return aggregateResult(records, cfg.ipNet, cfg.ports), nil
}

// sendMDNSQueries 做少量重试，兼顾 mDNS 响应延迟和避免组播风暴。
func sendMDNSQueries(conn *net.UDPConn, addr *net.UDPAddr, queries map[string]struct{}, retries int) error {
	for retry := 0; retry < retries; retry++ {
		for query := range queries {
			if err := sendMDNSQuery(conn, addr, query); err != nil {
				return err
			}
		}
		if retry+1 < retries {
			time.Sleep(150 * time.Millisecond)
		}
	}
	return nil
}

// sendMDNSQuery 构造标准 PTR 查询并发送到 mDNS IPv4 组播地址。
func sendMDNSQuery(conn *net.UDPConn, addr *net.UDPAddr, serviceType string) error {
	packet := buildDNSQuery(serviceType, dnsTypePTR)
	if _, err := conn.WriteToUDP(packet, addr); err != nil {
		return fmt.Errorf("send mDNS query %q: %w", serviceType, err)
	}
	return nil
}

// discoveredServiceTypes 从 _services._dns-sd._udp.local 的 PTR 响应中提取新服务类型。
func discoveredServiceTypes(records []dnsRecord) []string {
	var serviceTypes []string
	for _, record := range records {
		if record.Type != dnsTypePTR {
			continue
		}
		if record.Name == "_services._dns-sd._udp.local" && isServiceType(record.PTR) {
			serviceTypes = appendUnique(serviceTypes, record.PTR)
		}
	}
	return serviceTypes
}
