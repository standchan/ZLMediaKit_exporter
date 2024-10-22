package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"

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

var (
	/*
		BuildVersion, BuildDate, BuildCommitSha are filled in by the build script
	*/
	BuildVersion   = "<<< filled in by build >>>"
	BuildDate      = "<<< filled in by build >>>"
	BuildCommitSha = "<<< filled in by build >>>"
)

type metricInfo struct {
	Desc *prometheus.Desc
	Type prometheus.ValueType
}

var (
	ZLMediaKitInfo = prometheus.NewDesc(prometheus.BuildFQName(namespace, "zlm", "version_info"), "ZLMediaKit version info.", []string{"branchName", "buildTime", "commitHash"}, nil)
	ApiStatus      = prometheus.NewDesc(prometheus.BuildFQName(namespace, "api", "status"), "Shows the status of each API endpoint", []string{"endpoint"}, nil)

	// network threads metric
	// todo Threads指标可能用constLabels更好？
	NetworkThreadsTotal      = prometheus.NewDesc(prometheus.BuildFQName(namespace, "network", "threads_total"), "Total number of network threads", []string{}, nil)
	NetworkThreadsLoadTotal  = prometheus.NewDesc(prometheus.BuildFQName(namespace, "network", "threads_load_total"), "Total of network threads load", []string{}, nil)
	NetworkThreadsDelayTotal = prometheus.NewDesc(prometheus.BuildFQName(namespace, "network", "threads_delay_total"), "Total of network threads delay", []string{}, nil)

	// work threads metrics
	WorkThreadsTotal      = prometheus.NewDesc(prometheus.BuildFQName(namespace, "work", "threads_total"), "Total number of work threads", []string{}, nil)
	WorkThreadsLoadTotal  = prometheus.NewDesc(prometheus.BuildFQName(namespace, "work", "threads_load_total"), "Total of work threads load", []string{}, nil)
	WorkThreadsDelayTotal = prometheus.NewDesc(prometheus.BuildFQName(namespace, "work", "threads_delay_total"), "Total of work threads delay", []string{}, nil)

	// statistics metrics
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

	// server config metrics
	ServerApiInfo   = prometheus.NewDesc(prometheus.BuildFQName(namespace, "server", "api_info"), "Server config about api", []string{"apiDebug", "defaultSnap", "downloadRoot", "secret", "snapRoot"}, nil)
	ServerCluster   = prometheus.NewDesc(prometheus.BuildFQName(namespace, "server", "cluster_info"), "Server config about cluster", []string{"origin_url", "retry_Count", "timeout_sec"}, nil)
	ServerFFmpeg    = prometheus.NewDesc(prometheus.BuildFQName(namespace, "server", "ffmpeg_info"), "Server config about ffmpeg", []string{"bin", "cmd", "log", "restart_sec", "snap"}, nil)
	ServerGeneral   = prometheus.NewDesc(prometheus.BuildFQName(namespace, "server", "general_info"), "Server config about general", []string{"broadcast_player_count_changed", "check_nvidia_dev", "enableVhost", "enable_ffmpeg_log", "flowThreshold", "maxStreamWaitMS", "mediaServerId", "mergeWriteMS", "resetWhenRePlay", "streamNoneReaderDelayMS", "unready_frame_cache", "wait_add_track_ms", "wait_track_ready_ms"}, nil)
	ServerHls       = prometheus.NewDesc(prometheus.BuildFQName(namespace, "server", "hls_info"), "Server config about hls", []string{"broadcastRecordTs", "deleteDelaySec", "fastRegister", "fileBufSize", "segDelay", "segKeep", "segNum", "segRetain"}, nil)
	ServerHook      = prometheus.NewDesc(prometheus.BuildFQName(namespace, "server", "hook_info"), "Server config about hook", []string{"alive_interval", "enable", "on_flow_report", "on_http_access", "on_play", "on_publish", "on_record_mp4", "on_record_ts", "on_rtp_server_timeout", "on_rtsp_auth", "on_rtsp_realm", "on_send_rtp_stopped", "on_server_exited", "on_server_keepalive", "on_server_started", "on_shell_login", "on_stream_changed", "on_stream_none_reader", "on_stream_not_found", "retry", "retry_delay", "stream_changed_schemas", "timeoutSec"}, nil)
	ServerHTTP      = prometheus.NewDesc(prometheus.BuildFQName(namespace, "server", "http_info"), "Server config about http", []string{"allow_cross_domains", "allow_ip_range", "charSet", "dirMenu", "forbidCacheSuffix", "forwarded_ip_header", "keepAliveSecond", "maxReqSize", "notFound", "port", "rootPath", "sendBufSize", "sslport", "virtualPath"}, nil)
	ServerMulticast = prometheus.NewDesc(prometheus.BuildFQName(namespace, "server", "multicast_info"), "Server config about multicast", []string{"addrMax", "addrMin", "udpTTL"}, nil)
	ServerProtocol  = prometheus.NewDesc(prometheus.BuildFQName(namespace, "server", "protocol_info"), "Server config about protocol", []string{"add_mute_audio", "auto_close", "continue_push_ms", "enable_audio", "enable_fmp4", "enable_hls", "enable_hls_fmp4", "enable_mp4", "enable_rtmp", "enable_rtsp", "enable_ts", "fmp4_demand", "hls_demand", "hls_save_path", "modify_stamp", "mp4_as_player", "mp4_max_second", "mp4_save_path", "paced_sender_ms", "rtmp_demand", "rtsp_demand", "ts_demand"}, nil)
	ServerRecord    = prometheus.NewDesc(prometheus.BuildFQName(namespace, "server", "record_info"), "Server config about record", []string{"appName", "enableFmp4", "fastStart", "fileBufSize", "fileRepeat", "sampleMS"}, nil)
	ServerRtx       = prometheus.NewDesc(prometheus.BuildFQName(namespace, "server", "rtx_info"), "Server config about rtx", []string{"externIP", "maxNackMS", "max_bitrate", "min_bitrate", "nackIntervalRatio", "nackMaxCount", "nackMaxMS", "nackMaxSize", "nackRtpSize", "port", "preferredCodecA", "preferredCodecV", "rembBitRate", "rtpCacheCheckInterval", "start_bitrate", "tcpPort", "timeoutSec"}, nil)
	ServerRtmp      = prometheus.NewDesc(prometheus.BuildFQName(namespace, "server", "rtmp_info"), "Server config about rtmp", []string{"directProxy", "enhanced", "handshakeSecond", "keepAliveSecond", "port", "sslport"}, nil)
	ServerRtp       = prometheus.NewDesc(prometheus.BuildFQName(namespace, "server", "rtp_info"), "Server config about rtp", []string{"audioMtuSize", "h264_stap_a", "lowLatency", "rtpMaxSize", "videoMtuSize"}, nil)
	ServerRtpProxy  = prometheus.NewDesc(prometheus.BuildFQName(namespace, "server", "rtp_proxy_info"), "Server config about rtp_proxy", []string{"dumpDir", "gop_cache", "h264_pt", "h265_pt", "opus_pt", "port", "port_range", "ps_pt", "rtp_g711_dur_ms", "timeoutSec", "udp_recv_socket_buffer"}, nil)
	ServerRtsp      = prometheus.NewDesc(prometheus.BuildFQName(namespace, "server", "rtsp_info"), "Server config about rtsp", []string{"authBasic", "directProxy", "handshakeSecond", "keepAliveSecond", "lowLatency", "port", "rtpTransportType", "sslport"}, nil)
	ServerShell     = prometheus.NewDesc(prometheus.BuildFQName(namespace, "server", "shell_info"), "Server config about shell", []string{"maxReqSize", "port"}, nil)
	ServerSrt       = prometheus.NewDesc(prometheus.BuildFQName(namespace, "server", "srt_info"), "Server config about srt", []string{"latencyMul", "pktBufSize", "port", "timeoutSec"}, nil)

	// session metrics
	SessionInfo  = prometheus.NewDesc(prometheus.BuildFQName(namespace, "session", "session_info"), "Session info", []string{"id", "identifier", "local_ip", "local_port", "peer_ip", "peer_port", "typeid"}, nil)
	SessionTotal = prometheus.NewDesc(prometheus.BuildFQName(namespace, "session", "total"), "Total number of sessions", []string{}, nil)

	// stream metrics
	StreamTotal       = prometheus.NewDesc(prometheus.BuildFQName(namespace, "stream", "total"), "Total number of streams", []string{}, nil)
	StreamReaderCount = prometheus.NewDesc(prometheus.BuildFQName(namespace, "stream", "reader_count"), "Stream reader count", []string{"app", "stream", "schema", "vhost"}, nil)
	SteamBandwidth    = prometheus.NewDesc(prometheus.BuildFQName(namespace, "stream", "bandwidth"), "Stream bandwidth", []string{"app", "stream", "schema", "vhost", "originType"}, nil)

	// media metrics
	MediaPlayerInfo  = prometheus.NewDesc(prometheus.BuildFQName(namespace, "media", "player"), "Media player list", []string{"identifier", "local_ip", "local_port", "peer_ip", "peer_port", "typeid"}, nil)
	MediaPlayerTotal = prometheus.NewDesc(prometheus.BuildFQName(namespace, "media", "player_total"), "Total number of media players", []string{}, nil)

	// rtp metrics
	RtpServer      = prometheus.NewDesc(prometheus.BuildFQName(namespace, "rtp", "server"), "RTP server list", []string{"port", "stream_id"}, nil)
	RtpServerTotal = prometheus.NewDesc(prometheus.BuildFQName(namespace, "rtp", "server_total"), "Total number of RTP servers", []string{}, nil)
)

type Exporter struct {
	URI    string
	client http.Client
	mutex  sync.RWMutex

	up            prometheus.Gauge
	totalScrapes  prometheus.Counter
	serverMetrics map[int]metricInfo
	logger        *logrus.Logger
	options       Options

	buildInfo BuildInfo
}

type Options struct {
	ScrapeURI  string
	SSLVerify  bool
	CaCertFile string
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

	return exporter, nil
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	// todo:需要发送所有指标desc
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
	e.extractNetworkThreads(ch)
	e.extractWorkThreads(ch)
	e.extractStatistics(ch)
	e.extractServerConfig(ch)
	e.extractSession(ch)
	e.extractStream(ch)
	e.extractMedia(ch)
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
	header := http.Header{}
	header.Add("secret", ZLMSecret)
	uri := fmt.Sprintf("%s/%s", e.URI, endpoint)
	parsedURL, err := url.Parse(uri)
	if err != nil {
		e.logger.Println("msg", "Error parsing URL", "err", err)
		return
	}

	req := &http.Request{
		Method: http.MethodGet,
		URL:    parsedURL,
		Header: header,
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
func (e *Exporter) extractMedia(ch chan<- prometheus.Metric) {
	processFunc := func(body io.ReadCloser) error {
		var apiResponse APIResponseGeneric[[]map[string]interface{}]
		if err := json.NewDecoder(body).Decode(&apiResponse); err != nil {
			return fmt.Errorf("error decoding JSON response: %w", err)
		}
		if apiResponse.Code != 0 {
			return fmt.Errorf("unexpected API response code: %d", apiResponse.Code)
		}
		for i, v := range apiResponse.Data {
			identifier := fmt.Sprint(v["identifier"])
			localIP := fmt.Sprint(v["local_ip"])
			localPort := fmt.Sprint(v["local_port"])
			peerIp := fmt.Sprint(v["peer_ip"])
			peerPort := fmt.Sprint(v["peer_port"])
			typeid := fmt.Sprint(v["typeid"])
			ch <- prometheus.MustNewConstMetric(MediaPlayerInfo, prometheus.GaugeValue, float64(i), identifier, localIP, localPort, peerIp, peerPort, typeid)
		}
		ch <- prometheus.MustNewConstMetric(MediaPlayerTotal, prometheus.GaugeValue, float64(len(apiResponse.Data)))
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

// doc: https://prometheus.io/docs/instrumenting/writing_exporters/
// 1.metric must use base units
func main() {
	var (
		webConfig    = webflag.AddFlags(kingpin.CommandLine, ":9101")
		metricsPath  = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		zlmScrapeURI = kingpin.Flag("zlm.scrape-uri", "URI on which to scrape zlmediakit.").Default("http://localhost").String()
		zlmSSLVerify = kingpin.Flag("zlm.ssl-verify", "Flag that enables SSL certificate verification for the scrape URI").Default("true").Bool()
		logFormat    = kingpin.Flag("log-format", "Log format, valid options are txt and json").Default("").String()
	)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("zlm_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	log := logrus.New()

	switch *logFormat {
	case "json":
		log.SetFormatter(&logrus.JSONFormatter{})
	default:
		log.SetFormatter(&logrus.TextFormatter{})
	}
	log.SetLevel(logrus.InfoLevel)
	log.Println("msg", "Starting zlm_exporter", "version", version.Info())
	log.Println("msg", "Build context", "context", version.BuildContext())

	option := Options{
		ScrapeURI: *zlmScrapeURI,
		SSLVerify: *zlmSSLVerify,
	}

	exporter, err := NewExporter(log, option)
	if err != nil {
		log.Println("msg", "Error creating exporter", "err", err)
		os.Exit(1)
	}
	prometheus.MustRegister(exporter)

	//prometheus.MustRegister(version.NewCollector("zlm_exporter"))
	http.Handle(*metricsPath, promhttp.Handler())
	srv := &http.Server{}
	if err := web.ListenAndServe(srv, webConfig, promlog.New(promlogConfig)); err != nil {
		log.Error("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}

}
