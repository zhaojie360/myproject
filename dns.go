package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const (
	dnsTypeA    uint16 = 1
	dnsTypePTR  uint16 = 12
	dnsTypeTXT  uint16 = 16
	dnsTypeAAAA uint16 = 28
	dnsTypeSRV  uint16 = 33

	dnsClassIN uint16 = 1
)

// dnsRecord 是解码后的 DNS 资源记录，只填充当前扫描需要的记录类型字段。
type dnsRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32

	PTR string
	SRV *srvRecord
	TXT []string
	IP  net.IP
}

// srvRecord 保存 SRV 记录中的服务端口和目标主机名。
type srvRecord struct {
	Port   int
	Target string
}

// decodeDNSMessage 解析 DNS/mDNS 报文中的 answer、authority、additional 三类资源记录。
func decodeDNSMessage(packet []byte) ([]dnsRecord, error) {
	if len(packet) < 12 {
		return nil, fmt.Errorf("dns packet too short")
	}

	questionCount := int(binary.BigEndian.Uint16(packet[4:6]))
	answerCount := int(binary.BigEndian.Uint16(packet[6:8]))
	authorityCount := int(binary.BigEndian.Uint16(packet[8:10]))
	additionalCount := int(binary.BigEndian.Uint16(packet[10:12]))

	offset := 12
	for i := 0; i < questionCount; i++ {
		_, next, err := readDNSName(packet, offset)
		if err != nil {
			return nil, err
		}
		if next+4 > len(packet) {
			return nil, fmt.Errorf("question %d truncated", i)
		}
		offset = next + 4
	}

	totalRecords := answerCount + authorityCount + additionalCount
	records := make([]dnsRecord, 0, totalRecords)
	for i := 0; i < totalRecords; i++ {
		record, next, err := readDNSRecord(packet, offset)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
		offset = next
	}

	return records, nil
}

// readDNSRecord 根据记录类型解析 RDATA；暂不关心的类型保留基础元信息后跳过。
func readDNSRecord(packet []byte, offset int) (dnsRecord, int, error) {
	name, next, err := readDNSName(packet, offset)
	if err != nil {
		return dnsRecord{}, 0, err
	}
	if next+10 > len(packet) {
		return dnsRecord{}, 0, fmt.Errorf("resource record %q truncated", name)
	}

	recordType := binary.BigEndian.Uint16(packet[next : next+2])
	class := binary.BigEndian.Uint16(packet[next+2 : next+4])
	ttl := binary.BigEndian.Uint32(packet[next+4 : next+8])
	rdataLength := int(binary.BigEndian.Uint16(packet[next+8 : next+10]))
	rdataStart := next + 10
	rdataEnd := rdataStart + rdataLength
	if rdataEnd > len(packet) {
		return dnsRecord{}, 0, fmt.Errorf("resource record %q rdata truncated", name)
	}

	record := dnsRecord{
		Name:  canonicalName(name),
		Type:  recordType,
		Class: class & 0x7fff,
		TTL:   ttl,
	}

	switch recordType {
	case dnsTypePTR:
		target, _, err := readDNSName(packet, rdataStart)
		if err != nil {
			return dnsRecord{}, 0, err
		}
		record.PTR = canonicalName(target)
	case dnsTypeSRV:
		if rdataLength < 7 {
			return dnsRecord{}, 0, fmt.Errorf("srv record %q truncated", name)
		}
		port := binary.BigEndian.Uint16(packet[rdataStart+4 : rdataStart+6])
		target, _, err := readDNSName(packet, rdataStart+6)
		if err != nil {
			return dnsRecord{}, 0, err
		}
		record.SRV = &srvRecord{
			Port:   int(port),
			Target: canonicalName(target),
		}
	case dnsTypeTXT:
		txt, err := readTXT(packet[rdataStart:rdataEnd])
		if err != nil {
			return dnsRecord{}, 0, err
		}
		record.TXT = txt
	case dnsTypeA:
		if rdataLength != net.IPv4len {
			return dnsRecord{}, 0, fmt.Errorf("a record %q has invalid length %d", name, rdataLength)
		}
		record.IP = append(net.IP(nil), packet[rdataStart:rdataEnd]...)
	case dnsTypeAAAA:
		if rdataLength != net.IPv6len {
			return dnsRecord{}, 0, fmt.Errorf("aaaa record %q has invalid length %d", name, rdataLength)
		}
		record.IP = append(net.IP(nil), packet[rdataStart:rdataEnd]...)
	}

	return record, rdataEnd, nil
}

// readDNSName 支持普通 label 和 DNS 压缩指针，避免 mDNS 响应中的循环指针导致死循环。
func readDNSName(packet []byte, offset int) (string, int, error) {
	labels := make([]string, 0, 4)
	seenPointers := map[int]struct{}{}
	next := offset
	jumped := false

	for {
		if offset >= len(packet) {
			return "", 0, fmt.Errorf("dns name truncated")
		}

		length := int(packet[offset])
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(packet) {
				return "", 0, fmt.Errorf("dns compression pointer truncated")
			}
			pointer := int(binary.BigEndian.Uint16(packet[offset:offset+2]) & 0x3fff)
			if pointer >= len(packet) {
				return "", 0, fmt.Errorf("dns compression pointer out of range")
			}
			if _, ok := seenPointers[pointer]; ok {
				return "", 0, fmt.Errorf("dns compression pointer loop")
			}
			seenPointers[pointer] = struct{}{}
			if !jumped {
				next = offset + 2
				jumped = true
			}
			offset = pointer
			continue
		}
		if length&0xc0 != 0 {
			return "", 0, fmt.Errorf("unsupported dns label type")
		}

		offset++
		if length == 0 {
			if !jumped {
				next = offset
			}
			break
		}
		if offset+length > len(packet) {
			return "", 0, fmt.Errorf("dns label truncated")
		}

		labels = append(labels, string(packet[offset:offset+length]))
		offset += length
	}

	return strings.Join(labels, "."), next, nil
}

// readTXT 将 TXT RDATA 拆成多个 length-prefixed 字符串，后续再解析 key=value。
func readTXT(data []byte) ([]string, error) {
	var values []string
	for offset := 0; offset < len(data); {
		length := int(data[offset])
		offset++
		if offset+length > len(data) {
			return nil, fmt.Errorf("txt record truncated")
		}
		values = append(values, string(data[offset:offset+length]))
		offset += length
	}
	return values, nil
}

// buildDNSQuery 构造一个无事务 ID 的 mDNS 查询报文；mDNS 查询通常使用 ID=0。
func buildDNSQuery(name string, queryType uint16) []byte {
	packet := []byte{
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}
	packet = append(packet, packDNSName(name)...)
	packet = binary.BigEndian.AppendUint16(packet, queryType)
	packet = binary.BigEndian.AppendUint16(packet, dnsClassIN)
	return packet
}

// packDNSName 将 a.b.local 转换成 DNS wire format：长度字节 + label + 结尾 0。
func packDNSName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}
	}

	parts := strings.Split(name, ".")
	var out []byte
	for _, part := range parts {
		if part == "" {
			continue
		}
		out = append(out, byte(len(part)))
		out = append(out, []byte(part)...)
	}
	return append(out, 0)
}

// canonicalName 统一去掉尾部点，方便 map key 匹配和输出。
func canonicalName(name string) string {
	return strings.TrimSuffix(strings.TrimSpace(name), ".")
}
