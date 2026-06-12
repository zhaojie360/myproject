package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

type cliConfig struct {
	cidr          string
	ports         string
	timeout       time.Duration
	format        string
	interfaceName string
	retries       int
}

// scanConfig 是经过校验后的扫描配置，避免扫描逻辑重复处理字符串参数。
type scanConfig struct {
	ipNet         *net.IPNet
	ports         portFilter
	timeout       time.Duration
	interfaceName string
	retries       int
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run 保持可测试的 CLI 入口：解析参数、执行扫描、按指定格式输出。
func run(args []string, stdout io.Writer, stderr io.Writer) int {
	cfg, err := parseCLI(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	scanCfg, err := buildScanConfig(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), scanCfg.timeout)
	defer cancel()

	result, err := scanMDNS(ctx, scanCfg)
	if err != nil {
		fmt.Fprintf(stderr, "scan error: %v\n", err)
		return 1
	}

	switch cfg.format {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			fmt.Fprintf(stderr, "output error: %v\n", err)
			return 1
		}
	default:
		fmt.Fprint(stdout, formatText(result))
	}

	return 0
}

// parseCLI 只负责读取原始命令行参数，参数之间的语义校验交给 buildScanConfig。
func parseCLI(args []string, stderr io.Writer) (cliConfig, error) {
	var cfg cliConfig
	fs := flag.NewFlagSet("mdnsmap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.cidr, "cidr", "", "target CIDR, for example 192.168.1.0/24")
	fs.StringVar(&cfg.ports, "ports", "1-65535", "service ports to keep, for example 80,443,5000-6000")
	fs.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "scan timeout")
	fs.StringVar(&cfg.format, "format", "text", "output format: text or json")
	fs.StringVar(&cfg.interfaceName, "iface", "", "network interface name")
	fs.IntVar(&cfg.retries, "retries", 2, "mDNS query retry count")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if cfg.cidr == "" {
		fs.Usage()
		return cfg, fmt.Errorf("-cidr is required")
	}
	if cfg.timeout <= 0 {
		return cfg, fmt.Errorf("-timeout must be greater than 0")
	}
	if cfg.format != "text" && cfg.format != "json" {
		return cfg, fmt.Errorf("-format must be text or json")
	}
	if cfg.retries <= 0 {
		return cfg, fmt.Errorf("-retries must be greater than 0")
	}

	return cfg, nil
}

// buildScanConfig 将 CIDR、端口范围等用户输入转换成扫描阶段直接可用的数据结构。
func buildScanConfig(cfg cliConfig) (scanConfig, error) {
	_, ipNet, err := net.ParseCIDR(cfg.cidr)
	if err != nil {
		return scanConfig{}, fmt.Errorf("invalid CIDR %q: %w", cfg.cidr, err)
	}

	ports, err := parsePortFilter(cfg.ports)
	if err != nil {
		return scanConfig{}, fmt.Errorf("invalid ports %q: %w", cfg.ports, err)
	}

	return scanConfig{
		ipNet:         ipNet,
		ports:         ports,
		timeout:       cfg.timeout,
		interfaceName: cfg.interfaceName,
		retries:       cfg.retries,
	}, nil
}
