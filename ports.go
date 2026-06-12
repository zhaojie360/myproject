package main

import (
	"fmt"
	"strconv"
	"strings"
)

type portRange struct {
	start int
	end   int
}

// portFilter 支持单端口和闭区间端口段，例如 80,443,5000-6000。
type portFilter []portRange

// parsePortFilter 将 CLI 的端口参数解析为一组闭区间，并校验 1-65535 边界。
func parsePortFilter(input string) (portFilter, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("empty port range")
	}

	parts := strings.Split(input, ",")
	filter := make(portFilter, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty port segment")
		}

		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			start, err := parsePort(bounds[0])
			if err != nil {
				return nil, err
			}
			end, err := parsePort(bounds[1])
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("range start %d is greater than end %d", start, end)
			}
			filter = append(filter, portRange{start: start, end: end})
			continue
		}

		port, err := parsePort(part)
		if err != nil {
			return nil, err
		}
		filter = append(filter, portRange{start: port, end: port})
	}

	return filter, nil
}

// parsePort 解析单个端口值。
func parsePort(value string) (int, error) {
	value = strings.TrimSpace(value)
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", value)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %d out of range 1-65535", port)
	}
	return port, nil
}

// Contains 判断 SRV 记录中的端口是否命中用户输入的端口范围。
func (filter portFilter) Contains(port int) bool {
	for _, portRange := range filter {
		if port >= portRange.start && port <= portRange.end {
			return true
		}
	}
	return false
}
