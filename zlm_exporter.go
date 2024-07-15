package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors/version"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"github.com/sirupsen/logrus"
	"io"
	. "log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	namespace = "zlmediakit"
)

var (
	serverLabelNames = []string{"backend", "server"}
)

type metricInfo struct {
	Desc *prometheus.Desc
	Type prometheus.ValueType
}

type metrics map[int]metricInfo

func (m metrics) String() string {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	s := make([]string, len(keys))
	for i, k := range keys {
		s[i] = strconv.Itoa(k)
	}
	return strings.Join(s, ",")
}

var (
	serverMetrics  = metrics{}
	ZLMediaKitInfo = prometheus.NewDesc(prometheus.BuildFQName(namespace, "version", "info"), "ZLMediaKit version info.", []string{"branchName", "buildTime", "commitHash"}, nil)
	ApiStatus      = prometheus.NewDesc(prometheus.BuildFQName(namespace, "api", "status"), "Shows the status of each API endpoint", []string{"endpoint"}, nil)
)

type BuildInfo struct {
	Version   string
	CommitSha string
	Date      string
}

type Exporter struct {
	client http.Client

	mutex         sync.RWMutex
	up            prometheus.Gauge
	totalScrapes  prometheus.Counter
	serverMetrics map[int]metricInfo
	log           *logrus.Logger

	mux *http.ServeMux

	buildInfo BuildInfo
}

func NewExporter(logger *logrus.Logger) (*Exporter, error) {
	e := &Exporter{
		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "up",
			Help:      "Was the last scrape of ZLMediaKit successful.",
		}),
		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "exporter_scrapes_total",
			Help:      "Current total ZLMediaKit scrapes.",
		}),
		log: logger,
	}

	e.mux.HandleFunc("/", e.indexHandler)
	e.mux.HandleFunc("/scrape", e.scrapeHandler)
	e.mux.HandleFunc("/health", e.healthHandler)
}

func newServerMetric(metricName string, docString string, t prometheus.ValueType, constLabels prometheus.Labels) metricInfo {
	return metricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "server", metricName),
			docString,
			serverLabelNames,
			constLabels,
		),
		Type: t,
	}
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range e.serverMetrics {
		ch <- m.Desc
	}
	ch <- e.up.Desc()
	ch <- e.totalScrapes.Desc()
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	ch <- prometheus.MustNewConstMetric(e.up.Desc(), prometheus.GaugeValue, 1)
}

func (e *Exporter) scrapeHandler(ch chan<- prometheus.Metric) {
	e.totalScrapes.Inc()

	e.extractAPIVersion(ch)
}

func (e *Exporter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mux.ServeHTTP(w, r)
}

type APIResponse struct {
	Code int      `json:"code"`
	Data []string `json:"data"`
}

type versionInfo struct {
	BranchName string `json:"branchName"`
	BuildTime  string `json:"buildTime"`
	CommitHash string `json:"commitHash"`
}

func (e *Exporter) extractAPIVersion(ch chan<- prometheus.Metric) {
	header := http.Header{}
	//header.Add("secret", "xxxx")
	parsedURL, err := url.Parse("http://127.0.0.1/index/api/version")
	if err != nil {
		// 处理错误
		Fatal(err)
	}

	req := &http.Request{
		Method: http.MethodGet,
		URL:    parsedURL,
		Header: header,
	}

	res, err := e.client.Do(req)
	if err != nil {
		e.log.Error("msg", "Error scraping ZLMediaKit", "err", err)
	}
	defer res.Body.Close()

	var apiResponse APIResponse
	if err := json.NewDecoder(res.Body).Decode(&apiResponse); err != nil {
		e.log.Error("msg", "Error decoding JSON response", "err", err)
		//e.up.Inc()
		//ch <- prometheus.MustNewConstMetric(, prometheus.GaugeValue, e.up)
		return
	}
	if apiResponse.Code != 0 {
		e.log.Error("msg", "API response code is not 0", "code", apiResponse.Code)
		//e.up.Inc()
		//ch <- prometheus.MustNewConstMetric(, prometheus.GaugeValue, e.up)
		return
	}
	// 不知道apiResponse.Data中的字段排序会不会变化，这里直接传递给Desc可能有问题
	// todo: 不知道这样行不行
	ch <- prometheus.MustNewConstMetric(ZLMediaKitInfo, prometheus.GaugeValue, 1, apiResponse.Data...)
}

func (e *Exporter) healthHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(`ok`))
}

func (e *Exporter) indexHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(`<html>
<head><title>Redis Exporter ` + e.buildInfo.Version + `</title></head>
<body>
<h1>Redis Exporter ` + e.buildInfo.Version + `</h1>
<p><a href='` + `'>Metrics</a></p>
</body>
</html>
`))
}

func (e *Exporter) extractAPIStatus(ch chan<- prometheus.Metric) {
	header := http.Header{}
	header.Add("secret", "xxxx")
	parsedURL, err := url.Parse("http://127.0.0.1/index/api/getApiList")
	if err != nil {
		// 处理错误
		e.log.Error(err)
	}

	req := &http.Request{
		Method: http.MethodGet,
		URL:    parsedURL,
		Header: header,
	}

	res, err := e.client.Do(req)
	if err != nil {
		e.log.Error("msg", "Error scraping ZLMediaKit", "err", err)
	}
	defer res.Body.Close()

	var apiResponse APIResponse
	if err := json.NewDecoder(res.Body).Decode(&apiResponse); err != nil {
		e.log.Error(err)
		//e.up.Inc()
		//ch <- prometheus.MustNewConstMetric(, prometheus.GaugeValue, e.up)
		return
	}
	if apiResponse.Code != 0 {
		e.log.Error("msg", "API response code is not 0", "code", apiResponse.Code)
		//e.up.Inc()
		//ch <- prometheus.MustNewConstMetric(, prometheus.GaugeValue, e.up)
		return
	}
	for _, endpoint := range apiResponse.Data {
		ch <- prometheus.MustNewConstMetric(ApiStatus, prometheus.GaugeValue, 1, endpoint)
	}
}

func fetchHTTP(uri string, sslVerify, proxyFromEnv bool, timeout time.Duration) func() (io.ReadCloser, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !sslVerify}}
	if proxyFromEnv {
		tr.Proxy = http.ProxyFromEnvironment
	}
	client := http.Client{
		Timeout:   timeout,
		Transport: tr,
	}

	return func() (io.ReadCloser, error) {
		resp, err := client.Get(uri)
		if err != nil {
			return nil, err
		}
		if !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
		}
		return resp.Body, nil
	}
}

var (
	webConfig = webflag.AddFlags(kingpin.CommandLine, ":9101")
)

// doc: https://prometheus.io/docs/instrumenting/writing_exporters/
// 1.metric must use base units
func main() {
	log := logrus.New()

	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	log.SetLevel(logrus.InfoLevel)

	exporter, err := NewExporter(log)
	if err != nil {
		Fatalf("Error creating exporter: %s", err)
	}
	prometheus.MustRegister(exporter)
	prometheus.MustRegister(version.NewCollector("zlm_exporter"))

	server := &http.Server{
		Handler: exporter,
	}
	err = server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}

	// graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	_quit := <-quit
	log.Infof("Received %s signal, exiting", _quit.String())
	// Create a context with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shutdown the HTTP server gracefully
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}
	log.Infof("Server shut down gracefully")
}

// 当前方向
// 先把exporter运行起来，整体跑起来
// 后续再慢慢补充指标和优化代码
// 最后再补充测试代码和其他配置以及文档内容
