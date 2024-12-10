package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"context"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"github.com/sirupsen/logrus"
)

// todo: 考虑zlm版本更迭的api字段变动和废弃问题；可以用丢弃指标的方式来处理？
// todo: 提供所有的指标的文本版本
// todo: 提供grafana的演示地址
// todo：考虑暴露 metric 演示url
const (
	namespace = "zlmediakit"
)

func getEnv(key string, defaultVal string) string {
	if envVal, ok := os.LookupEnv(key); ok {
		return envVal
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if envVal, ok := os.LookupEnv(key); ok {
		envBool, err := strconv.ParseBool(envVal)
		if err == nil {
			return envBool
		}
	}
	return defaultVal
}

var (
	/*
		BuildVersion, BuildDate, BuildCommitSha are filled in by the build script
	*/
	BuildVersion   = "<<< filled in by build >>>"
	BuildDate      = "<<< filled in by build >>>"
	BuildCommitSha = "<<< filled in by build >>>"
)

var metrics []*prometheus.Desc

func newMetricDescr(namespace string, metricName string, docString string, labels []string) *prometheus.Desc {
	newDesc := prometheus.NewDesc(prometheus.BuildFQName(namespace, "", metricName), docString, labels, nil)
	metrics = append(metrics, newDesc)
	return newDesc
}

var (
	ZLMediaKitInfo = newMetricDescr(namespace, "version_info", "ZLMediaKit version info.", []string{"branchName", "buildTime", "commitHash"})
	ApiStatus      = newMetricDescr(namespace, "api_status", "The status of API endpoint", []string{"endpoint"})

	// network threads metric
	NetworkThreadsTotal      = newMetricDescr(namespace, "network_threads_total", "Total number of network threads", []string{})
	NetworkThreadsLoadTotal  = newMetricDescr(namespace, "network_threads_load_total", "Total of network threads load", []string{})
	NetworkThreadsDelayTotal = newMetricDescr(namespace, "network_threads_delay_total", "Total of network threads delay", []string{})

	// work threads metrics
	WorkThreadsTotal      = newMetricDescr(namespace, "work_threads_total", "Total number of work threads", []string{})
	WorkThreadsLoadTotal  = newMetricDescr(namespace, "work_threads_load_total", "Total of work threads load", []string{})
	WorkThreadsDelayTotal = newMetricDescr(namespace, "work_threads_delay_total", "Total of work threads delay", []string{})

	// statistics metrics
	StatisticsBuffer                = newMetricDescr(namespace, "statistics_buffer", "Statistics buffer", []string{})
	StatisticsBufferLikeString      = newMetricDescr(namespace, "statistics_buffer_like_string", "Statistics BufferLikeString", []string{})
	StatisticsBufferList            = newMetricDescr(namespace, "statistics_buffer_list", "Statistics BufferList", []string{})
	StatisticsBufferRaw             = newMetricDescr(namespace, "statistics_buffer_raw", "Statistics BufferRaw", []string{})
	StatisticsFrame                 = newMetricDescr(namespace, "statistics_frame", "Statistics Frame", []string{})
	StatisticsFrameImp              = newMetricDescr(namespace, "statistics_frame_imp", "Statistics FrameImp", []string{})
	StatisticsMediaSource           = newMetricDescr(namespace, "statistics_media_source", "Statistics MediaSource", []string{})
	StatisticsMultiMediaSourceMuxer = newMetricDescr(namespace, "statistics_multi_media_source_muxer", "Statistics MultiMediaSourceMuxer", []string{})
	StatisticsRtmpPacket            = newMetricDescr(namespace, "statistics_rtmp_packet", "Statistics RtmpPacket", []string{})
	StatisticsRtpPacket             = newMetricDescr(namespace, "statistics_rtp_packet", "Statistics RtpPacket", []string{})
	StatisticsSocket                = newMetricDescr(namespace, "statistics_socket", "Statistics Socket", []string{})
	StatisticsTcpClient             = newMetricDescr(namespace, "statistics_tcp_client", "Statistics TcpClient", []string{})
	StatisticsTcpServer             = newMetricDescr(namespace, "statistics_tcp_server", "Statistics TcpServer", []string{})
	StatisticsTcpSession            = newMetricDescr(namespace, "statistics_tcp_session", "Statistics TcpSession", []string{})
	StatisticsUdpServer             = newMetricDescr(namespace, "statistics_udp_server", "Statistics UdpServer", []string{})
	StatisticsUdpSession            = newMetricDescr(namespace, "statistics_udp_session", "Statistics UdpSession", []string{})

	// session metrics
	SessionInfo  = newMetricDescr(namespace, "session_info", "Session info", []string{"id", "identifier", "local_ip", "local_port", "peer_ip", "peer_port", "typeid"})
	SessionTotal = newMetricDescr(namespace, "session_total", "Total number of sessions", []string{})

	// stream metrics
	StreamTotal       = newMetricDescr(namespace, "stream_total", "Total number of streams", []string{})
	StreamReaderCount = newMetricDescr(namespace, "stream_reader_count", "Stream reader count", []string{"app", "stream", "schema", "vhost"})
	SteamBandwidth    = newMetricDescr(namespace, "stream_bandwidth", "Stream bandwidth", []string{"app", "stream", "schema", "vhost", "originType"})

	// rtp metrics
	RtpServerInfo  = newMetricDescr(namespace, "rtp_server", "RTP server info", []string{"port", "stream_id"})
	RtpServerTotal = newMetricDescr(namespace, "rtp_server_total", "Total number of RTP servers", []string{})
)

type Exporter struct {
	URI    string
	client http.Client
	mutex  sync.RWMutex

	up           prometheus.Gauge
	totalScrapes prometheus.Counter
	logger       *logrus.Logger
	options      Options

	buildInfo BuildInfo
}

type Options struct {
	ScrapeURI      string
	ClientCertFile string
	ClientKeyFile  string

	ServerCertFile   string
	ServerKeyFile    string
	ServerMinVersion string

	CaCertFile          string
	SkipTLSVerification bool
}

type BuildInfo struct {
	Version   string
	CommitSha string
	Date      string
}

func NewExporter(logger *logrus.Logger, options Options) (*Exporter, error) {
	exporter := &Exporter{
		URI: options.ScrapeURI,
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
		buildInfo: BuildInfo{
			Version:   BuildVersion,
			CommitSha: BuildCommitSha,
			Date:      BuildDate,
		},
		options: options,
	}

	exporter.client.Transport = &http.Transport{
		TLSClientConfig: exporter.CreateClientTLSConfig(),
	}

	return exporter, nil
}

func (e *Exporter) CreateClientTLSConfig() *tls.Config {
	tlsConfig := tls.Config{
		InsecureSkipVerify: e.options.SkipTLSVerification,
	}

	if e.options.ClientCertFile != "" && e.options.ClientKeyFile != "" {
		cert, err := LoadKeyPair(e.options.ClientCertFile, e.options.ClientKeyFile)
		if err != nil {
			log.Fatal(err)
		}
		tlsConfig.Certificates = []tls.Certificate{*cert}
	}

	if e.options.CaCertFile != "" {
		certificates, err := LoadCAFile(e.options.CaCertFile)
		if err != nil {
			log.Fatal(err)
		}
		tlsConfig.RootCAs = certificates
	} else {
		// Load the system certificate pool
		rootCAs, err := x509.SystemCertPool()
		if err != nil {
			log.Fatal(err)
		}

		tlsConfig.RootCAs = rootCAs
	}

	return &tlsConfig
}

func (e *Exporter) CreateServerTLSConfig(certFile, keyFile, caCertFile, minVersionString string) (*tls.Config, error) {
	// Verify that the initial key pair is accepted
	_, err := LoadKeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	// Get minimum acceptable TLS version from the config string
	minVersion, ok := tlsVersions[minVersionString]
	if !ok {
		return nil, fmt.Errorf("configured minimum TLS version unknown: '%s'", minVersionString)
	}

	tlsConfig := tls.Config{
		MinVersion:     minVersion,
		GetCertificate: GetServerCertificateFunc(certFile, keyFile),
	}

	if caCertFile != "" {
		// Verify that the initial CA file is accepted when configured
		_, err := LoadCAFile(caCertFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.GetConfigForClient = GetConfigForClientFunc(certFile, keyFile, caCertFile)
	}

	return &tlsConfig, nil
}

var tlsVersions = map[string]uint16{
	"TLS1.3": tls.VersionTLS13,
	"TLS1.2": tls.VersionTLS12,
	"TLS1.1": tls.VersionTLS11,
	"TLS1.0": tls.VersionTLS10,
}

// GetServerCertificateFunc returns a function for tls.Config.GetCertificate
func GetServerCertificateFunc(certFile, keyFile string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return LoadKeyPair(certFile, keyFile)
	}
}

// GetConfigForClientFunc returns a function for tls.Config.GetConfigForClient
func GetConfigForClientFunc(certFile, keyFile, caCertFile string) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(*tls.ClientHelloInfo) (*tls.Config, error) {
		certificates, err := LoadCAFile(caCertFile)
		if err != nil {
			return nil, err
		}

		tlsConfig := tls.Config{
			ClientAuth:     tls.RequireAndVerifyClientCert,
			ClientCAs:      certificates,
			GetCertificate: GetServerCertificateFunc(certFile, keyFile),
		}
		return &tlsConfig, nil
	}
}

// LoadKeyPair reads and parses a public/private key pair from a pair of files.
// The files must contain PEM encoded data.
func LoadKeyPair(certFile, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// LoadCAFile reads and parses CA certificates from a file into a pool.
// The file must contain PEM encoded data.
func LoadCAFile(caFile string) (*x509.CertPool, error) {
	pemCerts, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemCerts)
	return pool, nil
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	for _, metric := range metrics {
		ch <- metric
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
	e.extractNetworkThreads(ch)
	e.extractWorkThreads(ch)
	e.extractStatistics(ch)
	e.extractSession(ch)
	e.extractStream(ch)
	e.extractRtp(ch)
	return 1
}

type APIResponseDataThreads []struct {
	Load  float64 `json:"load"`
	Delay float64 `json:"delay"`
}

type APIResponseData interface {
	[]struct{} | map[string]interface{} | []map[string]string | []map[string]interface{} | []string | APIResponseDataThreads
}

type APIResponseGeneric[T APIResponseData] struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data T      `json:"data"`
}

func (e *Exporter) mustNewConstMetric(desc *prometheus.Desc, valueType prometheus.ValueType, value interface{}, labelValues ...string) prometheus.Metric {
	switch vt := value.(type) {
	case float64:
		return prometheus.MustNewConstMetric(desc, valueType, vt, labelValues...)
	case string:
		valueFloat, err := strconv.ParseFloat(vt, 64)
		if err == nil {
			return prometheus.MustNewConstMetric(desc, valueType, valueFloat, labelValues...)
		}
		return prometheus.MustNewConstMetric(desc, valueType, 1, labelValues...)
	default:
		return nil
	}
}

func (e *Exporter) fetchHTTP(ch chan<- prometheus.Metric, endpoint string, processFunc func(closer io.ReadCloser) error) {
	uri := fmt.Sprintf("%s/%s", e.URI, endpoint)
	parsedURL, err := url.Parse(uri)
	if err != nil {
		e.logger.Println("msg", "error parsing URL", "err", err)
		return
	}

	req := &http.Request{
		Method: http.MethodGet,
		URL:    parsedURL,
		Header: http.Header{
			"secret": []string{*zlmSecret},
		},
	}

	res, err := e.client.Do(req)
	if err != nil {
		e.logger.Println("msg", "error scraping ZLMediaKit", "err", err)
		return
	}
	defer res.Body.Close()

	if err = processFunc(res.Body); err != nil {
		e.logger.Println("msg", "error processing response", "err", err)
	}
}

func (e *Exporter) extractZLMVersion(ch chan<- prometheus.Metric) {
	processFunc := func(body io.ReadCloser) error {
		var apiResponse APIResponseGeneric[map[string]interface{}]
		if err := json.NewDecoder(body).Decode(&apiResponse); err != nil {
			return fmt.Errorf("error decoding JSON response: %w", err)
		}
		if apiResponse.Code != 0 {
			return fmt.Errorf("unexpected API response code: %d,reason: %s", apiResponse.Code, apiResponse.Msg)
		}
		data := apiResponse.Data
		ch <- prometheus.MustNewConstMetric(ZLMediaKitInfo, prometheus.GaugeValue, 1, data["branchName"].(string), data["buildTime"].(string), data["commitHash"].(string))
		return nil
	}
	e.fetchHTTP(ch, "index/api/version", processFunc)
}

func (e *Exporter) extractAPIStatus(ch chan<- prometheus.Metric) {
	processFunc := func(body io.ReadCloser) error {
		var apiResponse APIResponseGeneric[[]string]

		if err := json.NewDecoder(body).Decode(&apiResponse); err != nil {
			return fmt.Errorf("error decoding JSON response: %w", err)
		}
		if apiResponse.Code != 0 {
			return fmt.Errorf("unexpected API response code: %d,reason: %s", apiResponse.Code, apiResponse.Msg)
		}

		data := apiResponse.Data

		for _, endpoint := range data {
			ch <- prometheus.MustNewConstMetric(ApiStatus, prometheus.GaugeValue, 1, endpoint)
		}
		return nil
	}
	e.fetchHTTP(ch, "index/api/getApiList", processFunc)
}

func (e *Exporter) extractNetworkThreads(ch chan<- prometheus.Metric) {
	processFunc := func(body io.ReadCloser) error {
		var apiResponse APIResponseGeneric[APIResponseDataThreads]
		if err := json.NewDecoder(body).Decode(&apiResponse); err != nil {
			return fmt.Errorf("error decoding JSON response: %w", err)
		}
		if apiResponse.Code != 0 {
			return fmt.Errorf("unexpected API response code: %d,reason: %s", apiResponse.Code, apiResponse.Msg)
		}

		var loadTotal, delayTotal, total float64
		for _, data := range apiResponse.Data {
			loadTotal += data.Load
			delayTotal += data.Delay
			total++
		}
		ch <- prometheus.MustNewConstMetric(NetworkThreadsTotal, prometheus.GaugeValue, total)
		ch <- prometheus.MustNewConstMetric(NetworkThreadsLoadTotal, prometheus.GaugeValue, loadTotal)
		ch <- prometheus.MustNewConstMetric(NetworkThreadsDelayTotal, prometheus.GaugeValue, delayTotal)
		return nil
	}
	e.fetchHTTP(ch, "index/api/getThreadsLoad", processFunc)
}

func (e *Exporter) extractWorkThreads(ch chan<- prometheus.Metric) {
	processFunc := func(body io.ReadCloser) error {
		var apiResponse APIResponseGeneric[APIResponseDataThreads]
		if err := json.NewDecoder(body).Decode(&apiResponse); err != nil {
			return fmt.Errorf("error decoding JSON response: %w", err)
		}
		if apiResponse.Code != 0 {
			return fmt.Errorf("unexpected API response code: %d,reason: %s", apiResponse.Code, apiResponse.Msg)
		}
		var loadTotal, delayTotal, total float64
		for _, data := range apiResponse.Data {
			loadTotal += data.Load
			delayTotal += data.Delay
			total++
		}
		ch <- prometheus.MustNewConstMetric(WorkThreadsTotal, prometheus.GaugeValue, total)
		ch <- prometheus.MustNewConstMetric(WorkThreadsLoadTotal, prometheus.GaugeValue, loadTotal)
		ch <- prometheus.MustNewConstMetric(WorkThreadsDelayTotal, prometheus.GaugeValue, delayTotal)
		return nil
	}
	e.fetchHTTP(ch, "index/api/getWorkThreadsLoad", processFunc)
}

func (e *Exporter) extractStatistics(ch chan<- prometheus.Metric) {
	processFunc := func(body io.ReadCloser) error {
		var apiResponse APIResponseGeneric[map[string]interface{}]
		if err := json.NewDecoder(body).Decode(&apiResponse); err != nil {
			return fmt.Errorf("error decoding JSON response: %w", err)
		}
		if apiResponse.Code != 0 {
			return fmt.Errorf("unexpected API response code: %d,reason: %s", apiResponse.Code, apiResponse.Msg)
		}
		data := apiResponse.Data
		ch <- e.mustNewConstMetric(StatisticsBuffer, prometheus.GaugeValue, data["Buffer"])
		ch <- e.mustNewConstMetric(StatisticsBufferLikeString, prometheus.GaugeValue, data["BufferLikeString"])
		ch <- e.mustNewConstMetric(StatisticsBufferList, prometheus.GaugeValue, data["BufferList"])
		ch <- e.mustNewConstMetric(StatisticsBufferRaw, prometheus.GaugeValue, data["BufferRaw"])
		ch <- e.mustNewConstMetric(StatisticsFrame, prometheus.GaugeValue, data["Frame"])
		ch <- e.mustNewConstMetric(StatisticsFrameImp, prometheus.GaugeValue, data["FrameImp"])
		ch <- e.mustNewConstMetric(StatisticsMediaSource, prometheus.GaugeValue, data["MediaSource"])
		ch <- e.mustNewConstMetric(StatisticsMultiMediaSourceMuxer, prometheus.GaugeValue, data["MultiMediaSourceMuxer"])
		ch <- e.mustNewConstMetric(StatisticsRtmpPacket, prometheus.GaugeValue, data["RtmpPacket"])
		ch <- e.mustNewConstMetric(StatisticsRtpPacket, prometheus.GaugeValue, data["RtpPacket"])
		ch <- e.mustNewConstMetric(StatisticsSocket, prometheus.GaugeValue, data["Socket"])
		ch <- e.mustNewConstMetric(StatisticsTcpClient, prometheus.GaugeValue, data["TcpClient"])
		ch <- e.mustNewConstMetric(StatisticsTcpServer, prometheus.GaugeValue, data["TcpServer"])
		ch <- e.mustNewConstMetric(StatisticsTcpSession, prometheus.GaugeValue, data["TcpSession"])
		ch <- e.mustNewConstMetric(StatisticsUdpServer, prometheus.GaugeValue, data["UdpServer"])
		ch <- e.mustNewConstMetric(StatisticsUdpSession, prometheus.GaugeValue, data["UdpSession"])
		return nil
	}
	e.fetchHTTP(ch, "index/api/getStatistic", processFunc)
}

func (e *Exporter) extractSession(ch chan<- prometheus.Metric) {
	processFunc := func(body io.ReadCloser) error {
		var apiResponse APIResponseGeneric[[]map[string]interface{}]
		if err := json.NewDecoder(body).Decode(&apiResponse); err != nil {
			return fmt.Errorf("error decoding JSON response: %w", err)
		}
		if apiResponse.Code != 0 {
			return fmt.Errorf("unexpected API response code: %d,reason: %s", apiResponse.Code, apiResponse.Msg)
		}
		for _, v := range apiResponse.Data {
			id := fmt.Sprint(v["id"])
			identifier := fmt.Sprint(v["identifier"])
			localIP := fmt.Sprint(v["local_ip"])
			localPort := fmt.Sprint(v["local_port"])
			peerIP := fmt.Sprint(v["peer_ip"])
			peerPort := fmt.Sprint(v["peer_port"])
			typeID := fmt.Sprint(v["typeid"])
			ch <- prometheus.MustNewConstMetric(SessionInfo, prometheus.GaugeValue, 1, id, identifier, localIP, localPort, peerIP, peerPort, typeID)
		}
		ch <- prometheus.MustNewConstMetric(SessionTotal, prometheus.GaugeValue, float64(len(apiResponse.Data)))
		return nil
	}
	e.fetchHTTP(ch, "index/api/getAllSession", processFunc)
}

func (e *Exporter) extractStream(ch chan<- prometheus.Metric) {
	processFunc := func(body io.ReadCloser) error {
		var apiResponse APIResponseGeneric[[]map[string]interface{}]
		if err := json.NewDecoder(body).Decode(&apiResponse); err != nil {
			return fmt.Errorf("error decoding JSON response: %w", err)
		}
		if apiResponse.Code != 0 {
			return fmt.Errorf("unexpected API response code: %d,reason: %s", apiResponse.Code, apiResponse.Msg)
		}

		for _, v := range apiResponse.Data {
			app := fmt.Sprint(v["app"])
			stream := fmt.Sprint(v["stream"])
			schema := fmt.Sprint(v["schema"])
			readerCount, ok := v["readerCount"].(float64)
			if !ok {
				e.logger.Println("msg", "error converting readerCount to float64")
				continue
			}
			vhost := fmt.Sprint(v["vhost"])
			originType := fmt.Sprint(v["originType"])
			bytesSpeed, ok := v["bytesSpeed"].(float64)
			if !ok {
				e.logger.Println("msg", "error converting bytesSpeed to float64")
				continue
			}
			ch <- prometheus.MustNewConstMetric(StreamReaderCount, prometheus.GaugeValue, readerCount, app, stream, schema, vhost)
			ch <- prometheus.MustNewConstMetric(SteamBandwidth, prometheus.GaugeValue, bytesSpeed, app, stream, schema, vhost, originType)
		}
		ch <- prometheus.MustNewConstMetric(StreamTotal, prometheus.GaugeValue, float64(len(apiResponse.Data)))
		return nil
	}
	e.fetchHTTP(ch, "index/api/getMediaList", processFunc)
}

func (e *Exporter) extractRtp(ch chan<- prometheus.Metric) {
	processFunc := func(body io.ReadCloser) error {
		var apiResponse APIResponseGeneric[[]map[string]interface{}]
		if err := json.NewDecoder(body).Decode(&apiResponse); err != nil {
			return fmt.Errorf("error decoding JSON response: %w", err)
		}
		if apiResponse.Code != 0 {
			return fmt.Errorf("unexpected API response code: %d,reason: %s", apiResponse.Code, apiResponse.Msg)
		}
		for _, v := range apiResponse.Data {
			port := fmt.Sprint(v["port"])
			streamID := fmt.Sprint(v["stream_id"])
			ch <- prometheus.MustNewConstMetric(RtpServerInfo, prometheus.GaugeValue, 1, port, streamID)
		}
		ch <- prometheus.MustNewConstMetric(RtpServerTotal, prometheus.GaugeValue, float64(len(apiResponse.Data)))
		return nil
	}
	e.fetchHTTP(ch, "index/api/listRtpServer", processFunc)
}

func newLogger(logFormat, logLevel string) *logrus.Logger {
	logger := logrus.New()

	switch logFormat {
	case "json":
		logger.SetFormatter(&logrus.JSONFormatter{})
	default:
		logger.SetFormatter(&logrus.TextFormatter{})
	}

	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logger.Fatal(err)
	}
	logger.SetLevel(level)

	logger.Println("msg", "Starting zlm_exporter", "version", version.Info())
	logger.Println("msg", "Build context", "context", version.BuildContext())

	return logger
}

var (
	webConfig    = webflag.AddFlags(kingpin.CommandLine, ":9101")
	metricsPath  = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default(getEnv("ZLM_EXPORTER_METRICS_PATH", "/metrics")).String()
	zlmScrapeURI = kingpin.Flag("zlm.scrape-uri", "URI on which to scrape zlmediakit.").Default(getEnv("ZLM_EXPORTER_SCRAPE_URI", "http://localhost")).String()
	zlmSecret    = kingpin.Flag("zlm.secret", "Secret for the scrape URI").Default(getEnv("ZLM_EXPORTER_SECRET", "")).String()
	logFormat    = kingpin.Flag("zlm.log-format", "Log format, valid options are txt and json").Default(getEnv("ZLM_EXPORTER_LOG_FORMAT", "txt")).String()
	logLevel     = kingpin.Flag("zlm.log-level", "Log level, valid options are debug, info, warn, error, fatal, panic").Default(getEnv("ZLM_EXPORTER_LOG_LEVEL", "info")).String()

	tlsCACertFile = kingpin.Flag("tls.ca-cert-file", "Path to the CA certificate file").Default(getEnv("ZLM_EXPORTER_TLS_CA_CERT_FILE", "")).String()

	tlsClientCertFile = kingpin.Flag("tls.client-cert-file", "Path to the client certificate file").Default(getEnv("ZLM_EXPORTER_TLS_CLIENT_CERT_FILE", "")).String()
	tlsClientKeyFile  = kingpin.Flag("tls.client-key-file", "Path to the client key file").Default(getEnv("ZLM_EXPORTER_TLS_CLIENT_KEY_FILE", "")).String()

	tlsServerKeyFile    = kingpin.Flag("tls.server-key-file", "Path to the server key file").Default(getEnv("ZLM_EXPORTER_TLS_SERVER_KEY_FILE", "")).String()
	tlsServerCertFile   = kingpin.Flag("tls.server-cert-file", "Path to the server certificate file").Default(getEnv("ZLM_EXPORTER_TLS_SERVER_CERT_FILE", "")).String()
	tlsServerCaCertFile = kingpin.Flag("tls.server-ca-cert-file", "Path to the server CA certificate file").Default(getEnv("ZLM_EXPORTER_TLS_SERVER_CA_CERT_FILE", "")).String()
	tlsServerMinVersion = kingpin.Flag("tls.server-min-version", "Minimum TLS version supported").Default(getEnv("ZLM_EXPORTER_TLS_SERVER_MIN_VERSION", "")).String()
	skipTLSVerification = kingpin.Flag("tls.skip-verify", "Skip TLS verification").Default(getEnv("ZLM_EXPORTER_TLS_SKIP_VERIFY", "false")).Bool()
)

// doc: https://prometheus.io/docs/instrumenting/writing_exporters/
// 1.metric must use base units
func main() {

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("zlm_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	log := newLogger(*logFormat, *logLevel)

	option := Options{
		ScrapeURI:           *zlmScrapeURI,
		CaCertFile:          *tlsCACertFile,
		ClientCertFile:      *tlsClientCertFile,
		ClientKeyFile:       *tlsClientKeyFile,
		ServerCertFile:      *tlsServerCertFile,
		ServerKeyFile:       *tlsServerKeyFile,
		SkipTLSVerification: *skipTLSVerification,
	}

	exporter, err := NewExporter(log, option)
	if err != nil {
		log.Fatalln("msg", "Error creating exporter", "err", err)
	}

	// Verify that initial client keypair and CA are accepted
	if (*tlsClientCertFile != "") != (*tlsClientKeyFile != "") {
		log.Fatalln("TLS client key file and cert file should both be present")
	}

	exporter.CreateClientTLSConfig()

	prometheus.MustRegister(exporter)
	http.Handle(*metricsPath, promhttp.Handler())
	srv := &http.Server{}
	go func() {
		if *tlsServerCertFile != "" && *tlsServerKeyFile != "" {
			log.Debugf("Bind as TLS using cert %s and key %s", *tlsServerCertFile, *tlsServerKeyFile)

			tlsConfig, err := exporter.CreateServerTLSConfig(*tlsServerCertFile, *tlsServerKeyFile, *tlsServerCaCertFile, *tlsServerMinVersion)
			if err != nil {
				log.Fatalln(err)
			}
			srv.TLSConfig = tlsConfig
		}
		if err := web.ListenAndServe(srv, webConfig, promlog.New(promlogConfig)); err != nil {
			log.Fatalln("msg", "Error starting HTTP server", "err", err)
		}
		log.Infoln("zlm_exporter started successfully")
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		_quit := <-quit
		log.Infof("Received %s signal, exiting\n", _quit.String())

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		// Shutdown zlm_exporter gracefully
		if err := srv.Shutdown(ctx); err != nil {
			log.Fatalf("zlm_exporter shutdown failed: %v", err)
		}
		log.Infoln("zlm_exporter shutdown gracefully")
	}()

	<-quit
}
