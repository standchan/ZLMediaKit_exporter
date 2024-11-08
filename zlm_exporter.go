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
	ZLMediaKitInfo = newMetricDescr(namespace, "zlm_version_info", "ZLMediaKit version info.", []string{"branchName", "buildTime", "commitHash"})
	ApiStatus      = newMetricDescr(namespace, "api_status", "Shows the status of each API endpoint", []string{"endpoint"})

	// network threads metric
	// todo Threads指标可能用constLabels更好？
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

	// server config metrics
	ServerApiInfo   = newMetricDescr(namespace, "server_api_info", "Server config about api", []string{"apiDebug", "defaultSnap", "downloadRoot", "secret", "snapRoot"})
	ServerCluster   = newMetricDescr(namespace, "server_cluster_info", "Server config about cluster", []string{"origin_url", "retry_Count", "timeout_sec"})
	ServerFFmpeg    = newMetricDescr(namespace, "server_ffmpeg_info", "Server config about ffmpeg", []string{"bin", "cmd", "log", "restart_sec", "snap"})
	ServerGeneral   = newMetricDescr(namespace, "server_general_info", "Server config about general", []string{"broadcast_player_count_changed", "check_nvidia_dev", "enableVhost", "enable_ffmpeg_log", "flowThreshold", "maxStreamWaitMS", "mediaServerId", "mergeWriteMS", "resetWhenRePlay", "streamNoneReaderDelayMS", "unready_frame_cache", "wait_add_track_ms", "wait_track_ready_ms"})
	ServerHls       = newMetricDescr(namespace, "server_hls_info", "Server config about hls", []string{"broadcastRecordTs", "deleteDelaySec", "fastRegister", "fileBufSize", "segDelay", "segKeep", "segNum", "segRetain"})
	ServerHook      = newMetricDescr(namespace, "server_hook_info", "Server config about hook", []string{"alive_interval", "enable", "on_flow_report", "on_http_access", "on_play", "on_publish", "on_record_mp4", "on_record_ts", "on_rtp_server_timeout", "on_rtsp_auth", "on_rtsp_realm", "on_send_rtp_stopped", "on_server_exited", "on_server_keepalive", "on_server_started", "on_shell_login", "on_stream_changed", "on_stream_none_reader", "on_stream_not_found", "retry", "retry_delay", "stream_changed_schemas", "timeoutSec"})
	ServerHTTP      = newMetricDescr(namespace, "server_http_info", "Server config about http", []string{"allow_cross_domains", "allow_ip_range", "charSet", "dirMenu", "forbidCacheSuffix", "forwarded_ip_header", "keepAliveSecond", "maxReqSize", "notFound", "port", "rootPath", "sendBufSize", "sslport", "virtualPath"})
	ServerMulticast = newMetricDescr(namespace, "server_multicast_info", "Server config about multicast", []string{"addrMax", "addrMin", "udpTTL"})
	ServerProtocol  = newMetricDescr(namespace, "server_protocol_info", "Server config about protocol", []string{"add_mute_audio", "auto_close", "continue_push_ms", "enable_audio", "enable_fmp4", "enable_hls", "enable_hls_fmp4", "enable_mp4", "enable_rtmp", "enable_rtsp", "enable_ts", "fmp4_demand", "hls_demand", "hls_save_path", "modify_stamp", "mp4_as_player", "mp4_max_second", "mp4_save_path", "paced_sender_ms", "rtmp_demand", "rtsp_demand", "ts_demand"})
	ServerRecord    = newMetricDescr(namespace, "server_record_info", "Server config about record", []string{"appName", "enableFmp4", "fastStart", "fileBufSize", "fileRepeat", "sampleMS"})
	ServerRtx       = newMetricDescr(namespace, "server_rtx_info", "Server config about rtx", []string{"externIP", "maxNackMS", "max_bitrate", "min_bitrate", "nackIntervalRatio", "nackMaxCount", "nackMaxMS", "nackMaxSize", "nackRtpSize", "port", "preferredCodecA", "preferredCodecV", "rembBitRate", "rtpCacheCheckInterval", "start_bitrate", "tcpPort", "timeoutSec"})
	ServerRtmp      = newMetricDescr(namespace, "server_rtmp_info", "Server config about rtmp", []string{"directProxy", "enhanced", "handshakeSecond", "keepAliveSecond", "port", "sslport"})
	ServerRtp       = newMetricDescr(namespace, "server_rtp_info", "Server config about rtp", []string{"audioMtuSize", "h264_stap_a", "lowLatency", "rtpMaxSize", "videoMtuSize"})
	ServerRtpProxy  = newMetricDescr(namespace, "server_rtp_proxy_info", "Server config about rtp_proxy", []string{"dumpDir", "gop_cache", "h264_pt", "h265_pt", "opus_pt", "port", "port_range", "ps_pt", "rtp_g711_dur_ms", "timeoutSec", "udp_recv_socket_buffer"})
	ServerRtsp      = newMetricDescr(namespace, "server_rtsp_info", "Server config about rtsp", []string{"authBasic", "directProxy", "handshakeSecond", "keepAliveSecond", "lowLatency", "port", "rtpTransportType", "sslport"})
	ServerShell     = newMetricDescr(namespace, "server_shell_info", "Server config about shell", []string{"maxReqSize", "port"})
	ServerSrt       = newMetricDescr(namespace, "server_srt_info", "Server config about srt", []string{"latencyMul", "pktBufSize", "port", "timeoutSec"})

	// session metrics
	SessionInfo  = newMetricDescr(namespace, "session_info", "Session info", []string{"id", "identifier", "local_ip", "local_port", "peer_ip", "peer_port", "typeid"})
	SessionTotal = newMetricDescr(namespace, "session_total", "Total number of sessions", []string{})

	// stream metrics
	StreamTotal       = newMetricDescr(namespace, "stream_total", "Total number of streams", []string{})
	StreamReaderCount = newMetricDescr(namespace, "stream_reader_count", "Stream reader count", []string{"app", "stream", "schema", "vhost"})
	SteamBandwidth    = newMetricDescr(namespace, "stream_bandwidth", "Stream bandwidth", []string{"app", "stream", "schema", "vhost", "originType"})

	// rtp metrics
	RtpServer      = newMetricDescr(namespace, "rtp_server", "RTP server list", []string{"port", "stream_id"})
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
	e.extractServerConfig(ch)
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
	Code int `json:"code"`
	Data T   `json:"data"`
}

func (e *Exporter) fetchHTTP(ch chan<- prometheus.Metric, endpoint string, processFunc func(closer io.ReadCloser) error) {
	uri := fmt.Sprintf("%s/%s", e.URI, endpoint)
	parsedURL, err := url.Parse(uri)
	if err != nil {
		e.logger.Println("msg", "Error parsing URL", "err", err)
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
		e.logger.Println("msg", "Error scraping ZLMediaKit", "err", err)
		return
	}
	defer res.Body.Close()

	if err = processFunc(res.Body); err != nil {
		e.logger.Println("msg", "Error processing response", "err", err)
	}
}

func (e *Exporter) extractZLMVersion(ch chan<- prometheus.Metric) {
	fetchFunc := func(body io.ReadCloser) error {
		var apiResponse APIResponseGeneric[map[string]interface{}]
		if err := json.NewDecoder(body).Decode(&apiResponse); err != nil {
			return fmt.Errorf("error decoding JSON response: %w", err)
		}
		if apiResponse.Code != 0 {
			return fmt.Errorf("unexpected API response code: %d", apiResponse.Code)
		}
		data := apiResponse.Data
		ch <- prometheus.MustNewConstMetric(ZLMediaKitInfo, prometheus.GaugeValue, 1, data["branchName"].(string), data["buildTime"].(string), data["commitHash"].(string))
		return nil
	}
	e.fetchHTTP(ch, "index/api/version", fetchFunc)
}
func (e *Exporter) extractAPIStatus(ch chan<- prometheus.Metric) {
	processFunc := func(body io.ReadCloser) error {
		var apiResponse APIResponseGeneric[[]string]

		if err := json.NewDecoder(body).Decode(&apiResponse); err != nil {
			return fmt.Errorf("error decoding JSON response: %w", err)
		}
		if apiResponse.Code != 0 {
			return fmt.Errorf("unexpected API response code: %d", apiResponse.Code)
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
		var threadsLoad APIResponseGeneric[APIResponseDataThreads]
		if err := json.NewDecoder(body).Decode(&threadsLoad); err != nil {
			return fmt.Errorf("error decoding JSON response: %w", err)
		}
		if threadsLoad.Code != 0 {
			return fmt.Errorf("unexpected API response code: %d", threadsLoad.Code)
		}

		var loadTotal, delayTotal, total float64
		for _, data := range threadsLoad.Data {
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
		var threadsLoad APIResponseGeneric[APIResponseDataThreads]
		if err := json.NewDecoder(body).Decode(&threadsLoad); err != nil {
			return fmt.Errorf("error decoding JSON response: %w", err)
		}
		if threadsLoad.Code != 0 {
			return fmt.Errorf("unexpected API response code: %d", threadsLoad.Code)
		}
		var loadTotal, delayTotal, total float64
		for _, data := range threadsLoad.Data {
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
			return fmt.Errorf("unexpected API response code: %d", apiResponse.Code)
		}
		data := apiResponse.Data
		ch <- prometheus.MustNewConstMetric(StatisticsBuffer, prometheus.GaugeValue, data["Buffer"].(float64))
		ch <- prometheus.MustNewConstMetric(StatisticsBufferLikeString, prometheus.GaugeValue, data["BufferLikeString"].(float64))
		ch <- prometheus.MustNewConstMetric(StatisticsBufferList, prometheus.GaugeValue, data["BufferList"].(float64))
		ch <- prometheus.MustNewConstMetric(StatisticsBufferRaw, prometheus.GaugeValue, data["BufferRaw"].(float64))
		ch <- prometheus.MustNewConstMetric(StatisticsFrame, prometheus.GaugeValue, data["Frame"].(float64))
		ch <- prometheus.MustNewConstMetric(StatisticsFrameImp, prometheus.GaugeValue, data["FrameImp"].(float64))
		ch <- prometheus.MustNewConstMetric(StatisticsMediaSource, prometheus.GaugeValue, data["MediaSource"].(float64))
		ch <- prometheus.MustNewConstMetric(StatisticsMultiMediaSourceMuxer, prometheus.GaugeValue, data["MultiMediaSourceMuxer"].(float64))
		ch <- prometheus.MustNewConstMetric(StatisticsRtmpPacket, prometheus.GaugeValue, data["RtmpPacket"].(float64))
		ch <- prometheus.MustNewConstMetric(StatisticsRtpPacket, prometheus.GaugeValue, data["RtpPacket"].(float64))
		ch <- prometheus.MustNewConstMetric(StatisticsSocket, prometheus.GaugeValue, data["Socket"].(float64))
		ch <- prometheus.MustNewConstMetric(StatisticsTcpClient, prometheus.GaugeValue, data["TcpClient"].(float64))
		ch <- prometheus.MustNewConstMetric(StatisticsTcpServer, prometheus.GaugeValue, data["TcpServer"].(float64))
		ch <- prometheus.MustNewConstMetric(StatisticsTcpSession, prometheus.GaugeValue, data["TcpSession"].(float64))
		ch <- prometheus.MustNewConstMetric(StatisticsUdpServer, prometheus.GaugeValue, data["UdpServer"].(float64))
		ch <- prometheus.MustNewConstMetric(StatisticsUdpSession, prometheus.GaugeValue, data["UdpSession"].(float64))
		return nil
	}
	e.fetchHTTP(ch, "index/api/getStatistic", processFunc)
}

// todo: 这个指标可能没多大必要
func (e *Exporter) extractServerConfig(ch chan<- prometheus.Metric) {
	processFunc := func(body io.ReadCloser) error {
		var apiResponse APIResponseGeneric[[]map[string]string]
		if err := json.NewDecoder(body).Decode(&apiResponse); err != nil {
			return fmt.Errorf("error decoding JSON response: %w", err)
		}
		if apiResponse.Code != 0 {
			return fmt.Errorf("unexpected API response code: %d", apiResponse.Code)
		}

		for i, v := range apiResponse.Data {
			ch <- prometheus.MustNewConstMetric(ServerApiInfo, prometheus.GaugeValue, float64(i), v["api.apiDebug"], v["api.defaultSnap"], v["api.downloadRoot"], v["api.secret"], v["api.snapRoot"])
			ch <- prometheus.MustNewConstMetric(ServerCluster, prometheus.GaugeValue, float64(i), v["cluster.origin_url"], v["cluster.retry_Count"], v["cluster.timeout_sec"])
			ch <- prometheus.MustNewConstMetric(ServerFFmpeg, prometheus.GaugeValue, float64(i), v["ffmpeg.bin"], v["ffmpeg.cmd"], v["ffmpeg.log"], v["ffmpeg.restart_sec"], v["ffmpeg.snap"])
			ch <- prometheus.MustNewConstMetric(ServerGeneral, prometheus.GaugeValue, float64(i), v["general.broadcast_player_count_changed"], v["general.check_nvidia_dev"], v["general.enableVhost"], v["general.enable_ffmpeg_log"], v["general.flowThreshold"], v["general.maxStreamWaitMS"], v["general.mediaServerId"], v["general.mergeWriteMS"], v["general.resetWhenRePlay"], v["general.streamNoneReaderDelayMS"], v["general.unready_frame_cache"], v["general.wait_add_track_ms"], v["general.wait_track_ready_ms"])
			ch <- prometheus.MustNewConstMetric(ServerHls, prometheus.GaugeValue, float64(i), v["hls.broadcastRecordTs"], v["hls.deleteDelaySec"], v["hls.fastRegister"], v["hls.fileBufSize"], v["hls.segDelay"], v["hls.segKeep"], v["hls.segNum"], v["hls.segRetain"])
			ch <- prometheus.MustNewConstMetric(ServerHook, prometheus.GaugeValue, float64(i), v["hook.alive_interval"], v["hook.enable"], v["hook.on_flow_report"], v["hook.on_http_access"], v["hook.on_play"], v["hook.on_publish"], v["hook.on_record_mp4"], v["hook.on_record_ts"], v["hook.on_rtp_server_timeout"], v["hook.on_rtsp_auth"], v["hook.on_rtsp_realm"], v["hook.on_send_rtp_stopped"], v["hook.on_server_exited"], v["hook.on_server_keepalive"], v["hook.on_server_started"], v["hook.on_shell_login"], v["hook.on_stream_changed"], v["hook.on_stream_none_reader"], v["hook.on_stream_not_found"], v["hook.retry"], v["hook.retry_delay"], v["hook.stream_changed_schemas"], v["hook.timeoutSec"])
			ch <- prometheus.MustNewConstMetric(ServerHTTP, prometheus.GaugeValue, float64(i), v["http.allow_cross_domains"], v["http.allow_ip_range"], v["http.charSet"], v["http.dirMenu"], v["http.forbidCacheSuffix"], v["http.forwarded_ip_header"], v["http.keepAliveSecond"], v["http.maxReqSize"], v["http.notFound"], v["http.port"], v["http.rootPath"], v["http.sendBufSize"], v["http.sslport"], v["http.virtualPath"])
			ch <- prometheus.MustNewConstMetric(ServerMulticast, prometheus.GaugeValue, float64(i), v["multicast.addrMax"], v["multicast.addrMin"], v["multicast.udpTTL"])
			ch <- prometheus.MustNewConstMetric(ServerProtocol, prometheus.GaugeValue, float64(i), v["protocol.add_mute_audio"], v["protocol.auto_close"], v["protocol.continue_push_ms"], v["protocol.enable_audio"], v["protocol.enable_fmp4"], v["protocol.enable_hls"], v["protocol.enable_hls_fmp4"], v["protocol.enable_mp4"], v["protocol.enable_rtmp"], v["protocol.enable_rtsp"], v["protocol.enable_ts"], v["protocol.fmp4_demand"], v["protocol.hls_demand"], v["protocol.hls_save_path"], v["protocol.modify_stamp"], v["protocol.mp4_as_player"], v["protocol.mp4_max_second"], v["protocol.mp4_save_path"], v["protocol.paced_sender_ms"], v["protocol.rtmp_demand"], v["protocol.rtsp_demand"], v["protocol.ts_demand"])
			ch <- prometheus.MustNewConstMetric(ServerRecord, prometheus.GaugeValue, float64(i), v["record.appName"], v["record.enableFmp4"], v["record.fastStart"], v["record.fileBufSize"], v["record.fileRepeat"], v["record.sampleMS"])
			ch <- prometheus.MustNewConstMetric(ServerRtx, prometheus.GaugeValue, float64(i), v["rtx.externIP"], v["rtx.maxNackMS"], v["rtx.max_bitrate"], v["rtx.min_bitrate"], v["rtx.nackIntervalRatio"], v["rtx.nackMaxCount"], v["rtx.nackMaxMS"], v["rtx.nackMaxSize"], v["rtx.nackRtpSize"], v["rtx.port"], v["rtx.preferredCodecA"], v["rtx.preferredCodecV"], v["rtx.rembBitRate"], v["rtx.rtpCacheCheckInterval"], v["rtx.start_bitrate"], v["rtx.tcpPort"], v["rtx.timeoutSec"])
			ch <- prometheus.MustNewConstMetric(ServerRtmp, prometheus.GaugeValue, float64(i), v["rtmp.directProxy"], v["rtmp.enhanced"], v["rtmp.handshakeSecond"], v["rtmp.keepAliveSecond"], v["rtmp.port"], v["rtmp.sslport"])
			ch <- prometheus.MustNewConstMetric(ServerRtp, prometheus.GaugeValue, float64(i), v["rtp.audioMtuSize"], v["rtp.h264_stap_a"], v["rtp.lowLatency"], v["rtp.rtpMaxSize"], v["rtp.videoMtuSize"])
			ch <- prometheus.MustNewConstMetric(ServerRtpProxy, prometheus.GaugeValue, float64(i), v["rtp_proxy.dumpDir"], v["rtp_proxy.gop_cache"], v["rtp_proxy.h264_pt"], v["rtp_proxy.h265_pt"], v["rtp_proxy.opus_pt"], v["rtp_proxy.port"], v["rtp_proxy.port_range"], v["rtp_proxy.ps_pt"], v["rtp_proxy.rtp_g711_dur_ms"], v["rtp_proxy.timeoutSec"], v["rtp_proxy.udp_recv_socket_buffer"])
			ch <- prometheus.MustNewConstMetric(ServerRtsp, prometheus.GaugeValue, float64(i), v["rtsp.authBasic"], v["rtsp.directProxy"], v["rtsp.handshakeSecond"], v["rtsp.keepAliveSecond"], v["rtsp.lowLatency"], v["rtsp.port"], v["rtsp.rtpTransportType"], v["rtsp.sslport"])
			ch <- prometheus.MustNewConstMetric(ServerShell, prometheus.GaugeValue, float64(i), v["shell.maxReqSize"], v["shell.port"])
			ch <- prometheus.MustNewConstMetric(ServerSrt, prometheus.GaugeValue, float64(i), v["srt.latencyMul"], v["srt.pktBufSize"], v["srt.port"], v["srt.timeoutSec"])
		}

		return nil
	}
	e.fetchHTTP(ch, "index/api/getServerConfig", processFunc)
}
func (e *Exporter) extractSession(ch chan<- prometheus.Metric) {
	processFunc := func(body io.ReadCloser) error {
		var apiResponse APIResponseGeneric[[]map[string]interface{}]
		if err := json.NewDecoder(body).Decode(&apiResponse); err != nil {
			return fmt.Errorf("error decoding JSON response: %w", err)
		}
		if apiResponse.Code != 0 {
			return fmt.Errorf("unexpected API response code: %d", apiResponse.Code)
		}
		for i, v := range apiResponse.Data {
			id := fmt.Sprint(v["id"])
			identifier := fmt.Sprint(v["identifier"])
			localIP := fmt.Sprint(v["local_ip"])
			localPort := fmt.Sprint(v["local_port"])
			peerIP := fmt.Sprint(v["peer_ip"])
			peerPort := fmt.Sprint(v["peer_port"])
			typeID := fmt.Sprint(v["typeid"])
			ch <- prometheus.MustNewConstMetric(SessionInfo, prometheus.GaugeValue, float64(i), id, identifier, localIP, localPort, peerIP, peerPort, typeID)
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
			return fmt.Errorf("unexpected API response code: %d", apiResponse.Code)
		}

		for _, v := range apiResponse.Data {
			app := fmt.Sprint(v["app"])
			stream := fmt.Sprint(v["stream"])
			schema := fmt.Sprint(v["schema"])
			readerCount, ok := v["totalReaderCount"].(float64)
			if !ok {
				e.logger.Println("msg", "Error converting totalReaderCount to float64")
				continue
				// todo error handle
			}
			vhost := fmt.Sprint(v["vhost"])
			originType := fmt.Sprint(v["originType"])
			bytesSpeed, ok := v["bytesSpeed"].(float64)
			if !ok {
				e.logger.Println("msg", "Error converting bytesSpeed to float64")
				continue
				// todo error handle
			}
			// 如果一个scrapy中，发送重复的数据，就会报错
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
			return fmt.Errorf("unexpected API response code: %d", apiResponse.Code)
		}
		for i, v := range apiResponse.Data {
			port := fmt.Sprint(v["port"])
			streamID := fmt.Sprint(v["stream_id"])
			ch <- prometheus.MustNewConstMetric(RtpServer, prometheus.GaugeValue, float64(i), port, streamID)
		}
		ch <- prometheus.MustNewConstMetric(RtpServerTotal, prometheus.GaugeValue, float64(len(apiResponse.Data)))
		return nil
	}
	e.fetchHTTP(ch, "index/api/listRtpServer", processFunc)
}

var (
	webConfig    = webflag.AddFlags(kingpin.CommandLine, ":9101")
	metricsPath  = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default(getEnv("ZLM_EXPORTER_METRICS_PATH", "/metrics")).String()
	zlmScrapeURI = kingpin.Flag("zlm.scrape-uri", "URI on which to scrape zlmediakit.").Default(getEnv("ZLM_EXPORTER_SCRAPE_URI", "http://localhost")).String()
	zlmSecret    = kingpin.Flag("zlm.secret", "Secret for the scrape URI").Default(getEnv("ZLM_EXPORTER_SECRET", "")).String()
	logFormat    = kingpin.Flag("zlm.log-format", "Log format, valid options are txt and json").Default(getEnv("ZLM_EXPORTER_LOG_FORMAT", "txt")).String()
	logLevel     = kingpin.Flag("zlm.log-level", "Log level, valid options are debug, info, warn, error, fatal, panic").Default(getEnv("ZLM_EXPORTER_LOG_LEVEL", "info")).String()

	tlsClientCertFile = kingpin.Flag("tls.client-cert-file", "Path to the client certificate file").Default(getEnv("ZLM_EXPORTER_TLS_CLIENT_CERT_FILE", "")).String()
	tlsClientKeyFile  = kingpin.Flag("tls.client-key-file", "Path to the client key file").Default(getEnv("ZLM_EXPORTER_TLS_CLIENT_KEY_FILE", "")).String()

	tlsCACertFile       = kingpin.Flag("tls.ca-cert-file", "Path to the CA certificate file").Default(getEnv("ZLM_EXPORTER_TLS_CA_CERT_FILE", "")).String()
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

	logger := logrus.New()

	switch *logFormat {
	case "json":
		logger.SetFormatter(&logrus.JSONFormatter{})
	default:
		logger.SetFormatter(&logrus.TextFormatter{})
	}
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logger.Fatal(err)
	}
	logger.SetLevel(level)
	logger.Println("msg", "Starting zlm_exporter", "version", version.Info())
	logger.Println("msg", "Build context", "context", version.BuildContext())

	option := Options{
		ScrapeURI:           *zlmScrapeURI,
		ClientCertFile:      *tlsClientCertFile,
		ClientKeyFile:       *tlsClientKeyFile,
		ServerCertFile:      *tlsServerCertFile,
		ServerKeyFile:       *tlsServerKeyFile,
		CaCertFile:          *tlsCACertFile,
		SkipTLSVerification: *skipTLSVerification,
	}

	exporter, err := NewExporter(logger, option)
	if err != nil {
		logger.Println("msg", "Error creating exporter", "err", err)
		os.Exit(1)
	}

	// Verify that initial client keypair and CA are accepted
	if (*tlsClientCertFile != "") != (*tlsClientKeyFile != "") {
		logger.Fatal("TLS client key file and cert file should both be present")
	}

	exporter.CreateClientTLSConfig()

	prometheus.MustRegister(exporter)
	http.Handle(*metricsPath, promhttp.Handler())
	srv := &http.Server{}
	go func() {
		if *tlsServerCertFile != "" && *tlsServerKeyFile != "" {
			logger.Debugf("Bind as TLS using cert %s and key %s", *tlsServerCertFile, *tlsServerKeyFile)

			tlsConfig, err := exporter.CreateServerTLSConfig(*tlsServerCertFile, *tlsServerKeyFile, *tlsServerCaCertFile, *tlsServerMinVersion)
			if err != nil {
				logger.Fatal(err)
			}
			srv.TLSConfig = tlsConfig
			if err := web.ListenAndServe(srv, webConfig, promlog.New(promlogConfig)); err != nil {
				logger.Fatal("msg", "Error starting HTTP server", "err", err)
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		_quit := <-quit
		logger.Infof("Received %s signal, exiting", _quit.String())

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Shutdown server gracefully
		if err := srv.Shutdown(ctx); err != nil {
			logger.Fatalf("Server shutdown failed: %v", err)
		}
		logger.Infof("Server shut down gracefully")
	}()

	<-quit
}
