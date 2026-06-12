package main

import (
	"maps"
	"net"
	"slices"
	"sort"
	"strings"
)

// Asset 是最终输出的一条 mDNS 资产，来自 PTR/SRV/TXT/A/AAAA 多条记录的聚合。
type Asset struct {
	IP        string            `json:"ip,omitempty"`
	IPv6      string            `json:"ipv6,omitempty"`
	Port      int               `json:"port,omitempty"`
	Proto     string            `json:"proto,omitempty"`
	Service   string            `json:"service"`
	Name      string            `json:"name"`
	Hostname  string            `json:"host"`
	TTL       uint32            `json:"ttl,omitempty"`
	Banner    map[string]string `json:"banner,omitempty"`
	BannerRaw []string          `json:"banner_raw,omitempty"`
}

// Answers 保存原始发现到的答案摘要，目前主要输出 PTR 服务类型。
type Answers struct {
	PTR []string `json:"PTR,omitempty"`
}

// ScanResult 是 CLI text/json 两种输出格式共用的结果模型。
type ScanResult struct {
	Services []Asset `json:"services"`
	Answers  Answers `json:"answers"`
}

// instanceState 保存同一个服务实例在不同 DNS 记录中逐步补齐的信息。
type instanceState struct {
	serviceType string
	srv         *srvRecord
	txt         []string
	ttl         uint32
}

// aggregateResult 将离散 DNS 记录聚合成资产，并按用户输入的 CIDR 与端口范围过滤。
func aggregateResult(records []dnsRecord, ipNet *net.IPNet, ports portFilter) ScanResult {
	serviceTypes := map[string]struct{}{}
	instances := map[string]*instanceState{}
	ipv4ByHost := map[string][]string{}
	ipv6ByHost := map[string][]string{}

	for _, record := range records {
		name := canonicalName(record.Name)
		switch record.Type {
		case dnsTypePTR:
			// _services 查询返回的是服务类型；普通服务类型查询返回的是具体实例。
			if name == "_services._dns-sd._udp.local" {
				serviceTypes[record.PTR] = struct{}{}
				continue
			}
			if isServiceType(name) {
				serviceTypes[name] = struct{}{}
				state := ensureInstance(instances, record.PTR)
				state.serviceType = name
				mergeTTL(&state.ttl, record.TTL)
			}
		case dnsTypeSRV:
			state := ensureInstance(instances, name)
			state.srv = record.SRV
			mergeTTL(&state.ttl, record.TTL)
		case dnsTypeTXT:
			state := ensureInstance(instances, name)
			state.txt = appendUnique(state.txt, record.TXT...)
			mergeTTL(&state.ttl, record.TTL)
		case dnsTypeA:
			if record.IP != nil {
				ipv4ByHost[name] = appendUnique(ipv4ByHost[name], record.IP.String())
			}
		case dnsTypeAAAA:
			if record.IP != nil {
				ipv6ByHost[name] = appendUnique(ipv6ByHost[name], record.IP.String())
			}
		}
	}

	result := ScanResult{
		Services: make([]Asset, 0, len(instances)),
		Answers:  Answers{PTR: sortedKeys(serviceTypes)},
	}

	for instance, state := range instances {
		if state.srv == nil {
			continue
		}
		if !ports.Contains(state.srv.Port) {
			continue
		}

		hostname := canonicalName(state.srv.Target)
		ipv4s := ipv4ByHost[hostname]
		ipv6s := ipv6ByHost[hostname]
		// 输入网段只过滤解析到的 A/AAAA 地址，不对每个 IP 主动探测。
		if !matchesCIDR(ipv4s, ipv6s, ipNet) {
			continue
		}

		serviceType := state.serviceType
		if serviceType == "" {
			serviceType = inferServiceType(instance)
		}
		service, proto := parseServiceType(serviceType)
		banner := parseBanner(state.txt)

		result.Services = append(result.Services, Asset{
			IP:        first(ipv4s),
			IPv6:      first(ipv6s),
			Port:      state.srv.Port,
			Proto:     proto,
			Service:   service,
			Name:      instanceLabel(instance, serviceType),
			Hostname:  hostname,
			TTL:       state.ttl,
			Banner:    banner,
			BannerRaw: append([]string(nil), state.txt...),
		})
	}

	sort.Slice(result.Services, func(i, j int) bool {
		return compareAssets(result.Services[i], result.Services[j]) < 0
	})

	return result
}

// compareAssets 保证输出稳定，便于人工比对和自动化测试。
func compareAssets(left Asset, right Asset) int {
	if value := strings.Compare(left.IP, right.IP); value != 0 {
		return value
	}
	if left.Port != right.Port {
		return left.Port - right.Port
	}
	if value := strings.Compare(left.Hostname, right.Hostname); value != 0 {
		return value
	}
	if value := strings.Compare(left.Service, right.Service); value != 0 {
		return value
	}
	if value := strings.Compare(left.Proto, right.Proto); value != 0 {
		return value
	}
	return strings.Compare(left.Name, right.Name)
}

// ensureInstance 返回服务实例的聚合状态，不存在时创建。
func ensureInstance(instances map[string]*instanceState, name string) *instanceState {
	name = canonicalName(name)
	if instances[name] == nil {
		instances[name] = &instanceState{}
	}
	return instances[name]
}

// mergeTTL 保留较小 TTL，表示这组聚合信息中最短的有效时间。
func mergeTTL(current *uint32, ttl uint32) {
	if ttl == 0 {
		return
	}
	if *current == 0 || ttl < *current {
		*current = ttl
	}
}

// isServiceType 判断 _http._tcp.local 这类 DNS-SD 服务类型。
func isServiceType(name string) bool {
	parts := strings.Split(canonicalName(name), ".")
	return len(parts) >= 3 && strings.HasPrefix(parts[0], "_") && (parts[1] == "_tcp" || parts[1] == "_udp")
}

// inferServiceType 在缺少 PTR 记录时，从实例名中反推服务类型。
func inferServiceType(instance string) string {
	parts := strings.Split(canonicalName(instance), ".")
	for i := 0; i+2 < len(parts); i++ {
		if strings.HasPrefix(parts[i], "_") && (parts[i+1] == "_tcp" || parts[i+1] == "_udp") {
			return strings.Join(parts[i:i+3], ".")
		}
	}
	return ""
}

// parseServiceType 将 _http._tcp.local 拆成 http/tcp，便于按题目示例展示。
func parseServiceType(serviceType string) (string, string) {
	parts := strings.Split(canonicalName(serviceType), ".")
	if len(parts) < 2 {
		return serviceType, ""
	}
	return strings.TrimPrefix(parts[0], "_"), strings.TrimPrefix(parts[1], "_")
}

// instanceLabel 从 slw-nas._http._tcp.local 中提取 slw-nas 作为资产名称。
func instanceLabel(instance string, serviceType string) string {
	instance = canonicalName(instance)
	serviceType = canonicalName(serviceType)
	if serviceType != "" {
		suffix := "." + serviceType
		if strings.HasSuffix(instance, suffix) {
			return strings.TrimSuffix(instance, suffix)
		}
	}
	if index := strings.Index(instance, "."); index >= 0 {
		return instance[:index]
	}
	return instance
}

// parseBanner 将 TXT 中的 key=value 拆成结构化 banner，同时保留原始 TXT 顺序用于文本输出。
func parseBanner(raw []string) map[string]string {
	if len(raw) == 0 {
		return nil
	}

	banner := make(map[string]string, len(raw))
	for _, item := range raw {
		key, value, ok := strings.Cut(item, "=")
		if !ok || key == "" {
			continue
		}
		banner[key] = value
	}
	return banner
}

// matchesCIDR 判断任意 IPv4/IPv6 地址是否落在用户指定网段内。
func matchesCIDR(ipv4s []string, ipv6s []string, ipNet *net.IPNet) bool {
	for _, value := range append(append([]string{}, ipv4s...), ipv6s...) {
		ip := net.ParseIP(value)
		if ip != nil && ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// appendUnique 保持插入顺序去重，用于 TXT、IP 和服务类型列表。
func appendUnique(values []string, additions ...string) []string {
	seen := make(map[string]struct{}, len(values)+len(additions))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, value := range additions {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		values = append(values, value)
		seen[value] = struct{}{}
	}
	return values
}

// sortedKeys 输出稳定的 map key 列表。
func sortedKeys(values map[string]struct{}) []string {
	keys := slices.Collect(maps.Keys(values))
	sort.Strings(keys)
	return keys
}

// first 返回列表首项，空列表时返回空字符串，方便可选字段输出。
func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
