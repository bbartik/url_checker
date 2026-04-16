package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"time"
)

const (
	ipCheckURL     = "https://checkip.amazonaws.com"
	requestTimeout = 15 * time.Second
	urlsFile       = "urls.txt"
	maxBodyRead    = 4096
)

type Result struct {
	URL        string
	Timestamp  time.Time
	StatusCode int
	LatencyMS  int64
	CertIssuer string
	ZscalerSSL bool // cert was replaced by a Zscaler CA — SSL inspection active
	ZscalerHdr bool // X-Zscaler-* headers present in response
	Blocked    bool // 403/407 or block-page body detected
	ErrMsg     string
}

func getPublicIP() string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(ipCheckURL)
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(body))
}

func checkURL(rawURL string) Result {
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}

	r := Result{
		URL:       rawURL,
		Timestamp: time.Now(),
	}

	var tlsState tls.ConnectionState
	hasTLS := false

	trace := &httptrace.ClientTrace{
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err == nil {
				tlsState = state
				hasTLS = true
			}
		},
	}

	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		r.ErrMsg = "bad URL: " + err.Error()
		return r
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64) zscaler-check/1.0")

	transport := &http.Transport{
		// InsecureSkipVerify so we can capture and inspect Zscaler-issued certs
		// without bailing on a verification error — we examine them manually below.
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// don't follow redirects — a redirect to a block page is itself a signal
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	resp, err := client.Do(req)
	r.LatencyMS = time.Since(start).Milliseconds()

	if err != nil {
		r.ErrMsg = classifyError(err)
		return r
	}
	defer resp.Body.Close()

	r.StatusCode = resp.StatusCode

	// read a snippet of the body to detect block pages
	bodyBuf, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	io.Copy(io.Discard, resp.Body)
	bodyLower := strings.ToLower(string(bodyBuf))

	// block detection: status code or block-page body keywords
	if resp.StatusCode == 403 || resp.StatusCode == 407 ||
		strings.Contains(bodyLower, "blocked by zscaler") ||
		strings.Contains(bodyLower, "access denied") ||
		strings.Contains(bodyLower, "this site is blocked") ||
		strings.Contains(bodyLower, "zscaler safe browsing") {
		r.Blocked = true
	}

	// Zscaler header detection
	for k := range resp.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-zscaler") {
			r.ZscalerHdr = true
			break
		}
	}

	// TLS cert analysis
	if hasTLS && len(tlsState.PeerCertificates) > 0 {
		cert := tlsState.PeerCertificates[0]
		issuer := cert.Issuer.CommonName
		if len(cert.Issuer.Organization) > 0 {
			issuer = cert.Issuer.Organization[0]
		}
		r.CertIssuer = issuer
		lc := strings.ToLower(issuer + " " + cert.Issuer.CommonName)
		r.ZscalerSSL = strings.Contains(lc, "zscaler")
	}

	return r
}

func classifyError(err error) string {
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "no such host") || strings.Contains(s, "dns"):
		return "DNS failure"
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline exceeded"):
		return "Timeout"
	case strings.Contains(s, "connection refused"):
		return "Connection refused"
	case strings.Contains(s, "certificate") || strings.Contains(s, "tls"):
		return "TLS error: " + err.Error()
	default:
		return err.Error()
	}
}

func printHeader() {
	fmt.Printf("%-52s  %-6s  %7s  %-26s  %-10s  %s\n",
		"URL", "STATUS", "LATENCY", "CERT ISSUER", "FLAGS", "TIMESTAMP")
	fmt.Println(strings.Repeat("-", 130))
}

func flags(r Result) string {
	var parts []string
	if r.ZscalerSSL {
		parts = append(parts, "Z-SSL")
	}
	if r.ZscalerHdr {
		parts = append(parts, "Z-HDR")
	}
	if r.Blocked {
		parts = append(parts, "BLOCK")
	}
	if len(parts) == 0 {
		return "ok"
	}
	return strings.Join(parts, " ")
}

func printResult(r Result) {
	ts := r.Timestamp.Format("Jan 02 15:04:05")

	if r.ErrMsg != "" {
		fmt.Printf("%-52s  %-6s  %7s  %-26s  %-10s  %s\n",
			trunc(r.URL, 52), "ERROR", "-", "-", "-", ts)
		fmt.Printf("    └─ %s\n", r.ErrMsg)
		return
	}

	certName := r.CertIssuer
	if certName == "" {
		certName = "n/a"
	}

	fmt.Printf("%-52s  %-6d  %5dms  %-26s  %-10s  %s\n",
		trunc(r.URL, 52), r.StatusCode, r.LatencyMS,
		trunc(certName, 26), flags(r), ts)
}

func trunc(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "~"
}

func writeCSV(results []Result, pubIP string) {
	fname := "results_" + time.Now().Format("20060102_150405") + ".csv"
	f, err := os.Create(fname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write CSV: %v\n", err)
		return
	}
	defer f.Close()

	w := csv.NewWriter(f)
	_ = w.Write([]string{
		"public_ip", "timestamp", "url", "status_code",
		"latency_ms", "cert_issuer", "zscaler_ssl", "zscaler_headers",
		"blocked", "error",
	})
	for _, r := range results {
		_ = w.Write([]string{
			pubIP,
			r.Timestamp.Format(time.RFC3339),
			r.URL,
			fmt.Sprint(r.StatusCode),
			fmt.Sprint(r.LatencyMS),
			r.CertIssuer,
			fmt.Sprint(r.ZscalerSSL),
			fmt.Sprint(r.ZscalerHdr),
			fmt.Sprint(r.Blocked),
			r.ErrMsg,
		})
	}
	w.Flush()
	fmt.Printf("\nresults saved → %s\n", fname)
}

func main() {
	pubIP := getPublicIP()
	fmt.Printf("pub ip: %s\n\n", pubIP)

	f, err := os.Open(urlsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open %s: %v\n", urlsFile, err)
		os.Exit(1)
	}
	defer f.Close()

	printHeader()

	var results []Result
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r := checkURL(line)
		results = append(results, r)
		printResult(r)
	}

	writeCSV(results, pubIP)
}
