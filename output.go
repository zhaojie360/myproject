package main

import (
	"fmt"
	"sort"
	"strings"
)

// formatText 按题目示例输出 services 和 answers 两个区块。
func formatText(result ScanResult) string {
	var builder strings.Builder
	builder.WriteString("services:\n")
	for _, service := range result.Services {
		if service.Port > 0 {
			fmt.Fprintf(&builder, "%d/%s %s:\n", service.Port, service.Proto, service.Service)
		} else {
			fmt.Fprintf(&builder, "%s:\n", service.Service)
		}
		if service.Name != "" {
			fmt.Fprintf(&builder, "Name=%s\n", service.Name)
		}
		if service.IP != "" {
			fmt.Fprintf(&builder, "IPv4=%s\n", service.IP)
		}
		if service.IPv6 != "" {
			fmt.Fprintf(&builder, "IPv6=%s\n", service.IPv6)
		}
		if service.Hostname != "" {
			fmt.Fprintf(&builder, "Hostname=%s\n", service.Hostname)
		}
		if service.TTL > 0 {
			fmt.Fprintf(&builder, "TTL=%d\n", service.TTL)
		}
		if banner := bannerLine(service); banner != "" {
			builder.WriteString(banner)
			builder.WriteByte('\n')
		}
	}

	builder.WriteString("answers:\n")
	builder.WriteString("PTR:\n")
	for _, ptr := range result.Answers.PTR {
		builder.WriteString(ptr)
		builder.WriteByte('\n')
	}

	return builder.String()
}

// bannerLine 优先使用原始 TXT 顺序，保证深度识别字段展示接近设备真实响应。
func bannerLine(service Asset) string {
	if len(service.BannerRaw) > 0 {
		return strings.Join(service.BannerRaw, ",")
	}
	if len(service.Banner) == 0 {
		return ""
	}

	keys := make([]string, 0, len(service.Banner))
	for key := range service.Banner {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+service.Banner[key])
	}
	return strings.Join(parts, ",")
}
