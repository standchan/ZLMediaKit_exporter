package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"

	"io"
	. "log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
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

type Exporter struct {
	client http.Client

	mutex         sync.RWMutex
	up            prometheus.Gauge
	totalScrapes  prometheus.Counter
	serverMetrics map[int]metricInfo
	log           log.Logger
}

func NewExporter(logger log.Logger) (*Exporter, error) {
	return &Exporter{
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
	}, nil
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

	up := e.scrapeHandler(ch)
	ch <- prometheus.MustNewConstMetric(e.up.Desc(), prometheus.GaugeValue, up)
}

func (e *Exporter) scrapeHandler(ch chan<- prometheus.Metric) (up float64) {
	e.totalScrapes.Inc()

	e.extractAPIVersion(ch)

	return 1
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
		e.log.Log("msg", "Error scraping ZLMediaKit", "err", err)
	}
	defer res.Body.Close()

	var apiResponse APIResponse
	if err := json.NewDecoder(res.Body).Decode(&apiResponse); err != nil {
		e.log.Log("msg", "Error decoding JSON response", "err", err)
		//e.up.Inc()
		//ch <- prometheus.MustNewConstMetric(, prometheus.GaugeValue, e.up)
		return
	}
	if apiResponse.Code != 0 {
		e.log.Log("msg", "API response code is not 0", "code", apiResponse.Code)
		//e.up.Inc()
		//ch <- prometheus.MustNewConstMetric(, prometheus.GaugeValue, e.up)
		return
	}
	// 不知道apiResponse.Data中的字段排序会不会变化，这里直接传递给Desc可能有问题
	// todo: 不知道这样行不行
	ch <- prometheus.MustNewConstMetric(ZLMediaKitInfo, prometheus.GaugeValue, 1, apiResponse.Data...)
}

func (e *Exporter) extractAPIStatus(ch chan<- prometheus.Metric) {
	header := http.Header{}
	header.Add("secret", "xxxx")
	parsedURL, err := url.Parse("http://127.0.0.1/index/api/getApiList")
	if err != nil {
		// 处理错误
		log.Fatal(err)
	}

	req := &http.Request{
		Method: http.MethodGet,
		URL:    parsedURL,
		Header: header,
	}

	res, err := e.client.Do(req)
	if err != nil {
		e.log.Println(res)
	}
	defer res.Body.Close()

	var apiResponse APIResponse
	if err := json.NewDecoder(res.Body).Decode(&apiResponse); err != nil {
		e.log.Println(err)
		//e.up.Inc()
		//ch <- prometheus.MustNewConstMetric(, prometheus.GaugeValue, e.up)
		return
	}
	if apiResponse.Code != 0 {
		e.log.Println(apiResponse)
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
	promlogConfig := &promlog.Config{}

	logger := promlog.New(promlogConfig)

	exporter, err := NewExporter(logger)
	if err != nil {
		Fatalf("Error creating exporter: %s", err)
	}
	prometheus.MustRegister(exporter)
	prometheus.MustRegister(version.NewCollector("zlm_exporter"))

	http.Handle("/", promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>ZLMediakit Exporter</title></head>
             <body>
             <h1>ZLMediakit Exporter</h1>
             <p><a href='` + "/" + `'>Metrics</a></p>
             </body>
             </html>`))
	})
	srv := &http.Server{}
	if err := web.ListenAndServe(srv, webConfig, logger); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}
}

// 当前方向
// 先把exporter运行起来，整体跑起来
// 后续再慢慢补充指标和优化代码
// 最后再补充测试代码和其他配置以及文档内容
