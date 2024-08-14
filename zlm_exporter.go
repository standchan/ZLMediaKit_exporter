package main

import (
	"encoding/json"
	"fmt"
	"github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
)

const (
	namespace = "zlmediakit"
	subsystem = "server"
)

var (
	serverLabelNames = []string{"backend", "server"}
)

type metricInfo struct {
	Desc *prometheus.Desc
	Type prometheus.ValueType
}

type metrics map[int]metricInfo

var (
	serverMetrics  = metrics{}
	ZLMediaKitInfo = prometheus.NewDesc(prometheus.BuildFQName(namespace, subsystem, "version_info"), "ZLMediaKit version info.", []string{"branchName", "buildTime", "commitHash"}, nil)
	ApiStatus      = prometheus.NewDesc(prometheus.BuildFQName(namespace, subsystem, "api_status"), "Shows the status of each API endpoint", []string{"endpoint"}, nil)

	// 网络线程相关指标
	// todo Threads指标可能用constLabels更好？
	Threads           = prometheus.NewDesc(prometheus.BuildFQName(namespace, subsystem, "threads"), "Network threads", []string{"load", "delay"}, nil)
	ThreadsTotal      = prometheus.NewDesc(prometheus.BuildFQName(namespace, subsystem, "threads_total"), "Total number of network threads", []string{}, nil)
	ThreadsLoadTotal  = prometheus.NewDesc(prometheus.BuildFQName(namespace, subsystem, "threads_load_total"), "Total number of network threads load", []string{}, nil)
	ThreadsDelayTotal = prometheus.NewDesc(prometheus.BuildFQName(namespace, subsystem, "threads_delay_total"), "Total number of network threads delay", []string{}, nil)

	// 主要对象相关指标
	StatisticsBuffer                = prometheus.NewDesc(prometheus.BuildFQName(namespace, "statistics", "buffer"), "Statistics buffer", []string{}, nil)
	StatisticsBufferLikeString      = prometheus.NewDesc(prometheus.BuildFQName(namespace, "statistics", "buffer_like_string"), "Statistics BufferLikeString", []string{}, nil)
	StatisticsBufferList            = prometheus.NewDesc(prometheus.BuildFQName(namespace, "statistics", "buffer_list"), "Statistics BufferList", []string{}, nil)
	StatisticsBufferRaw             = prometheus.NewDesc(prometheus.BuildFQName(namespace, "statistics", "buffer_raw"), "Statistics BufferRaw", []string{}, nil)
	StatisticsFrame                 = prometheus.NewDesc(prometheus.BuildFQName(namespace, "statistics", "frame"), "Statistics Frame", []string{}, nil)
	StatisticsFrameImp              = prometheus.NewDesc(prometheus.BuildFQName(namespace, "statistics", "frame_imp"), "Statistics FrameImp", []string{}, nil)
	StatisticsMediaSource           = prometheus.NewDesc(prometheus.BuildFQName(namespace, "statistics", "media_source"), "Statistics MediaSource", []string{}, nil)
	StatisticsMultiMediaSourceMuxer = prometheus.NewDesc(prometheus.BuildFQName(namespace, "statistics", "multi_media_source_muxer"), "Statistics MultiMediaSourceMuxer", []string{}, nil)
	StatisticsRtmpPacket            = prometheus.NewDesc(prometheus.BuildFQName(namespace, "statistics", "rtmp_packet"), "Statistics RtmpPacket", []string{}, nil)
	StatisticsRtpPacket             = prometheus.NewDesc(prometheus.BuildFQName(namespace, "statistics", "rtp_packet"), "Statistics RtpPacket", []string{}, nil)
	StatisticsSocket                = prometheus.NewDesc(prometheus.BuildFQName(namespace, "statistics", "socket"), "Statistics Socket", []string{}, nil)
	StatisticsTcpClient             = prometheus.NewDesc(prometheus.BuildFQName(namespace, "statistics", "tcp_client"), "Statistics TcpClient", []string{}, nil)
	StatisticsTcpServer             = prometheus.NewDesc(prometheus.BuildFQName(namespace, "statistics", "tcp_server"), "Statistics TcpServer", []string{}, nil)
	StatisticsTcpSession            = prometheus.NewDesc(prometheus.BuildFQName(namespace, "statistics", "tcp_session"), "Statistics TcpSession", []string{}, nil)
	StatisticsUdpServer             = prometheus.NewDesc(prometheus.BuildFQName(namespace, "statistics", "udp_server"), "Statistics UdpServer", []string{}, nil)
	StatisticsUdpSession            = prometheus.NewDesc(prometheus.BuildFQName(namespace, "statistics", "udp_session"), "Statistics UdpSession", []string{}, nil)
)

type Exporter struct {
	client http.Client

	mutex         sync.RWMutex
	up            prometheus.Gauge
	totalScrapes  prometheus.Counter
	serverMetrics map[int]metricInfo
	logger        log.Logger

	mux *http.ServeMux

	buildInfo BuildInfo
}

type Options struct {
	Namespace string

	Registry  *prometheus.Registry
	BuildInfo BuildInfo
}

type BuildInfo struct {
	Version   string
	CommitSha string
	Date      string
}

func NewExporter(logger log.Logger, opts Options) (*Exporter, error) {
	exporter := &Exporter{
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
		logger: logger,
	}

	return exporter, nil
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
	up := e.scrape(ch)
	ch <- prometheus.MustNewConstMetric(e.up.Desc(), prometheus.GaugeValue, up)
	ch <- e.totalScrapes
}

func (e *Exporter) scrape(ch chan<- prometheus.Metric) (up float64) {
	e.totalScrapes.Inc()
	e.extractZLMVersion(ch)
	e.extractAPIStatus(ch)
	e.extractThreadsLoad(ch)
	return 1
}

type ZLMVersion struct {
	Code int               `json:"code"`
	Data map[string]string `json:"Data"`
}

type APIStatus struct {
	Code int      `json:"code"`
	Data []string `json:"Data"`
}

func (e *Exporter) fetchHTTP(ch chan<- prometheus.Metric, endpoint string, processFunc func(closer io.ReadCloser) error) {
	header := http.Header{}
	header.Add("secret", ZLMSecret)
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		level.Error(e.logger).Log("msg", "Error parsing URL", "err", err)
		return
	}

	req := &http.Request{
		Method: http.MethodGet,
		URL:    parsedURL,
		Header: header,
	}

	res, err := e.client.Do(req)
	if err != nil {
		level.Error(e.logger).Log("msg", "Error scraping ZLMediaKit", "err", err)
		return
	}
	defer res.Body.Close()

	if err = processFunc(res.Body); err != nil {
		level.Error(e.logger).Log("msg", "Error processing response", "err", err)
	}
}

func (e *Exporter) extractZLMVersion(ch chan<- prometheus.Metric) {
	fetchFunc := func(body io.ReadCloser) error {
		var apiResponse ZLMVersion
		if err := json.NewDecoder(body).Decode(&apiResponse); err != nil {
			return fmt.Errorf("error decoding JSON response: %w", err)
		}
		if apiResponse.Code != 0 {
			return fmt.Errorf("API response code is not 0: %d", apiResponse.Code)
		}
		ch <- prometheus.MustNewConstMetric(ZLMediaKitInfo, prometheus.GaugeValue, 1, apiResponse.Data["branchName"], apiResponse.Data["buildTime"], apiResponse.Data["commitHash"])
		return nil
	}
	e.fetchHTTP(ch, "http://127.0.0.1/index/api/version", fetchFunc)
}

func (e *Exporter) extractAPIStatus(ch chan<- prometheus.Metric) {
	processFunc := func(body io.ReadCloser) error {
		var apiResponse APIStatus
		if err := json.NewDecoder(body).Decode(&apiResponse); err != nil {
			return fmt.Errorf("error decoding JSON response: %w", err)
		}
		if apiResponse.Code != 0 {
			return fmt.Errorf("API response code is not 0: %d", apiResponse.Code)
		}
		for _, endpoint := range apiResponse.Data {
			ch <- prometheus.MustNewConstMetric(ApiStatus, prometheus.GaugeValue, 1, endpoint)
		}
		return nil
	}
	e.fetchHTTP(ch, "http://127.0.0.1/index/api/getApiList", processFunc)
}
func (e *Exporter) extractThreadsLoad(ch chan<- prometheus.Metric) {
	processFunc := func(body io.ReadCloser) error {
		type ThreadsLoad struct {
			Code int `json:"code"`
			Data []struct {
				Load  float64 `json:"load"`
				Delay float64 `json:"delay"`
			}
		}
		var threadsLoad ThreadsLoad
		if err := json.NewDecoder(body).Decode(&threadsLoad); err != nil {
			return fmt.Errorf("error decoding JSON response: %w", err)
		}
		if threadsLoad.Code != 0 {
			return fmt.Errorf("API response code is not 0: %d", threadsLoad.Code)
		}
		loadTotal := float64(0)
		delayTotal := float64(0)
		total := float64(0)
		for _, data := range threadsLoad.Data {
			loadTotal += data.Load
			delayTotal += data.Delay
			total++
		}
		ch <- prometheus.MustNewConstMetric(ThreadsTotal, prometheus.GaugeValue, total)
		ch <- prometheus.MustNewConstMetric(ThreadsLoadTotal, prometheus.GaugeValue, loadTotal)
		ch <- prometheus.MustNewConstMetric(ThreadsDelayTotal, prometheus.GaugeValue, delayTotal)
		return nil
	}
	e.fetchHTTP(ch, "http://127.0.0.1/index/api/getThreadsLoad", processFunc)
}

func (e *Exporter) extractStatistics(ch chan<- prometheus.Metric) {
	processFunc := func(body io.ReadCloser) error {
		type Statistics struct {
			Code int                    `json:"code"`
			Data map[string]interface{} `json:"Data"`
		}
	}
}

// doc: https://prometheus.io/docs/instrumenting/writing_exporters/
// 1.metric must use base units
func main() {
	var (
		webConfig   = webflag.AddFlags(kingpin.CommandLine, ":9101")
		metricsPath = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
	)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("zlm_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("msg", "Starting zlm_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "context", version.BuildContext())

	exporter, err := NewExporter(logger, Options{})
	if err != nil {
		level.Error(logger).Log("msg", "Error creating exporter", "err", err)
		return
	}
	prometheus.MustRegister(exporter)

	//prometheus.MustRegister(version.NewCollector("zlm_exporter"))
	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>ZLMediaKit Exporter</title></head>
             <body>
             <h1>Haproxy Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})
	srv := &http.Server{}
	if err := web.ListenAndServe(srv, webConfig, logger); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}

}

var apiURList = []string{
	"/index/api/getApiList",
}

// 当前方向
// 先把exporter运行起来，整体跑起来
// 后续再慢慢补充指标和优化代码
// 最后再补充测试代码和其他配置以及文档内容
