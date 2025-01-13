package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/gin-gonic/gin"
)

// most of unittest powered by cursor
// WIP
var (
	MockZlmServerPort    = "9999"
	MockZlmServerAddr    = fmt.Sprintf("localhost:%s", MockZlmServerPort)
	MockZlmServerSecret  = "test-secret"
	MockZlmServerHandler = gin.Default()

	TestServerHandler = gin.Default()
	TestServerAddr    = ":9101"
	TestServerSecret  = "test-secret"
)

func setup() {
	setupZlmApiServer()
}

func setupZlmApiServer() {
	r := MockZlmServerHandler
	r.GET("index/api/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, readTestData("version"))
	})

	r.GET("index/api/getApiList", func(c *gin.Context) {
		c.JSON(http.StatusOK, readTestData("getApiList"))
	})

	r.GET("index/api/getThreadsLoad", func(c *gin.Context) {
		c.JSON(http.StatusOK, readTestData("getThreadsLoad"))
	})

	r.GET("index/api/getWorkThreadsLoad", func(c *gin.Context) {
		c.JSON(http.StatusOK, readTestData("getWorkThreadsLoad"))
	})

	r.GET("index/api/getStatistic", func(c *gin.Context) {
		c.JSON(http.StatusOK, readTestData("getStatistic"))
	})

	r.GET("index/api/getServerConfig", func(c *gin.Context) {
		c.JSON(http.StatusOK, readTestData("getServerConfig"))
	})

	r.GET("index/api/getAllSession", func(c *gin.Context) {
		c.JSON(http.StatusOK, readTestData("getAllSession"))
	})

	r.GET("index/api/getMediaList", func(c *gin.Context) {
		c.JSON(http.StatusOK, readTestData("getMediaList"))
	})

	r.GET("index/api/listRtpServer", func(c *gin.Context) {
		c.JSON(http.StatusOK, readTestData("listRtpServer"))
	})

	go func() {
		err := r.Run(MockZlmServerAddr)
		if err != nil {
			log.Fatal(err)
		}
	}()
}

func readTestData(name string) map[string]any {
	file, err := os.ReadFile(fmt.Sprintf("testdata/api/%s.json", name))
	if err != nil {
		log.Fatal(err)
	}
	var fileJson map[string]any
	err = json.Unmarshal(file, &fileJson)
	if err != nil {
		log.Println(err)
	}
	return fileJson
}

func TestMetricsDescribe(t *testing.T) {
	tests := []struct {
		name          string
		metricsCount  int
		includeUpDesc bool
	}{
		{
			name:          "verify all metrics",
			metricsCount:  len(metrics) + 2,
			includeUpDesc: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logrus.New()
			options := Options{}
			exporter, err := NewExporter("http://localhost", MockZlmServerSecret, logger, options)
			assert.NoError(t, err)

			ch := make(chan *prometheus.Desc, tt.metricsCount)
			done := make(chan bool)

			go func() {
				exporter.Describe(ch)
				close(ch)
				done <- true
			}()

			descriptions := make([]*prometheus.Desc, 0)
			for desc := range ch {
				descriptions = append(descriptions, desc)
			}
			<-done

			assert.Equal(t, tt.metricsCount, len(descriptions), "metrics description count not match")

			descMap := make(map[string]bool)
			for _, desc := range descriptions {
				descMap[desc.String()] = true
			}

			for _, metric := range metrics {
				assert.True(t, descMap[metric.String()], "missing metric description: %s", metric.String())
			}

			assert.True(t, descMap[exporter.up.Desc().String()], "missing up metric description")
			assert.True(t, descMap[exporter.totalScrapes.Desc().String()], "missing totalScrapes metric description")

			keyMetrics := []struct {
				name     string
				desc     *prometheus.Desc
				expected bool
			}{
				{"ZLMediaKitInfo", ZLMediaKitInfo, true},
				{"ApiStatus", ApiStatus, true},
				{"NetworkThreadsTotal", NetworkThreadsTotal, true},
				{"StreamsInfo", StreamsInfo, true},
				{"SessionInfo", SessionInfo, true},
				{"RtpServerInfo", RtpServerInfo, true},
			}

			for _, km := range keyMetrics {
				assert.True(t, descMap[km.desc.String()], "missing key metric description: %s", km.name)
			}
		})
	}
}

func TestMetricsCollect(t *testing.T) {
	setup()
	tests := []struct {
		name          string
		metricsCount  int
		includeUpDesc bool
	}{
		// todo jerry-rig
		{
			name:          "verify all metrics",
			metricsCount:  2,
			includeUpDesc: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logrus.New()
			options := Options{}
			exporter, err := NewExporter(MockZlmServerAddr, MockZlmServerSecret, logger, options)
			assert.NoError(t, err)

			ch := make(chan prometheus.Metric, tt.metricsCount)
			done := make(chan bool)

			go func() {
				exporter.Collect(ch)
				close(ch)
				done <- true
			}()

			<-done

			metrics := make([]prometheus.Metric, 0)
			for metric := range ch {
				metrics = append(metrics, metric)
			}

			assert.Equal(t, tt.metricsCount, len(metrics), "metrics count not match")
		})
	}
}

func TestFetchHTTPErrorHandling(t *testing.T) {
	tests := []struct {
		name          string
		responseCode  int
		responseBody  string
		expectedError bool
	}{
		{
			name:          "success response",
			responseCode:  http.StatusOK,
			responseBody:  `{"code": 0, "msg": "success", "data": {}}`,
			expectedError: false,
		},
		{
			name:          "invalid json response",
			responseCode:  http.StatusOK,
			responseBody:  `invalid json`,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.responseCode)
				_, _ = w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			logger := logrus.New()
			options := Options{}
			exporter, err := NewExporter(server.URL, MockZlmServerSecret, logger, options)
			assert.NoError(t, err)

			ch := make(chan prometheus.Metric, 1)
			endpoint := "test/endpoint"

			processFunc := func(closer io.ReadCloser) error {
				var result map[string]interface{}
				if err := json.NewDecoder(closer).Decode(&result); err != nil {
					return err
				}
				return nil
			}

			exporter.fetchHTTP(ch, endpoint, processFunc)

			errorCount := testutil.ToFloat64(scrapeErrors.WithLabelValues(endpoint))
			if tt.expectedError {
				assert.Greater(t, errorCount, float64(0), "expected error but not recorded")
			} else {
				assert.Equal(t, float64(0), errorCount, "unexpected error recorded")
			}
		})
	}
}

func TestFetchHTTPConcurrency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code": 0, "msg": "success", "data": {}}`))
	}))
	defer server.Close()

	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter(server.URL, MockZlmServerSecret, logger, options)
	assert.NoError(t, err)

	ch := make(chan prometheus.Metric, 10)
	var wg sync.WaitGroup
	concurrentRequests := 5

	for i := 0; i < concurrentRequests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			endpoint := fmt.Sprintf("test/endpoint/%d", index)
			processFunc := func(closer io.ReadCloser) error {
				return nil
			}
			exporter.fetchHTTP(ch, endpoint, processFunc)
		}(i)
	}

	wg.Wait()
}

func TestMetricsRegistration(t *testing.T) {
	if ZLMediaKitInfo == nil {
		t.Error("ZLMediaKitInfo metric not initialized")
	}
	if ApiStatus == nil {
		t.Error("ApiStatus metric not initialized")
	}
	if NetworkThreadsTotal == nil {
		t.Error("NetworkThreadsTotal metric not initialized")
	}
	if NetworkThreadsLoadTotal == nil {
		t.Error("NetworkThreadsLoadTotal metric not initialized")
	}
	if WorkThreadsTotal == nil {
		t.Error("WorkThreadsTotal metric not initialized")
	}
	if WorkThreadsLoadTotal == nil {
		t.Error("WorkThreadsLoadTotal metric not initialized")
	}
	if StatisticsBuffer == nil {
		t.Error("StatisticsBuffer metric not initialized")
	}
	if StatisticsBufferLikeString == nil {
		t.Error("StatisticsBufferLikeString metric not initialized")
	}
	if StatisticsBufferList == nil {
		t.Error("StatisticsBufferList metric not initialized")
	}
	if StatisticsBufferRaw == nil {
		t.Error("StatisticsBufferRaw metric not initialized")
	}
	if StatisticsFrame == nil {
		t.Error("StatisticsFrame metric not initialized")
	}
	if StatisticsFrameImp == nil {
		t.Error("StatisticsFrameImp metric not initialized")
	}
	if StatisticsMediaSource == nil {
		t.Error("StatisticsMediaSource metric not initialized")
	}
	if StatisticsMultiMediaSourceMuxer == nil {
		t.Error("StatisticsMultiMediaSourceMuxer metric not initialized")
	}
	if StatisticsRtmpPacket == nil {
		t.Error("StatisticsRtmpPacket metric not initialized")
	}
	if StatisticsRtpPacket == nil {
		t.Error("StatisticsRtpPacket metric not initialized")
	}
	if StatisticsSocket == nil {
		t.Error("StatisticsSocket metric not initialized")
	}
	if StatisticsTcpClient == nil {
		t.Error("StatisticsTcpClient metric not initialized")
	}
	if StatisticsTcpServer == nil {
		t.Error("StatisticsTcpServer metric not initialized")
	}
	if StatisticsTcpSession == nil {
		t.Error("StatisticsTcpSession metric not initialized")
	}
	if StatisticsUdpServer == nil {
		t.Error("StatisticsUdpServer metric not initialized")
	}
	if StatisticsUdpSession == nil {
		t.Error("StatisticsUdpSession metric not initialized")
	}
	if StreamBandwidths == nil {
		t.Error("StreamBandwidths metric not initialized")
	}
	if StreamsInfo == nil {
		t.Error("StreamsInfo metric not initialized")
	}
	if StreamReaderCount == nil {
		t.Error("StreamReaderCount metric not initialized")
	}
	if StreamTotalReaderCount == nil {
		t.Error("StreamTotalReaderCount metric not initialized")
	}
}

func TestNewExporter(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		secret      string
		shouldError bool
	}{
		{
			name:        "有效的URI和Secret",
			uri:         "http://localhost:8080",
			secret:      MockZlmServerSecret,
			shouldError: false,
		},
		{
			name:        "空URI",
			uri:         "",
			secret:      MockZlmServerSecret,
			shouldError: true,
		},
		{
			name:        "空Secret",
			uri:         "http://localhost:8080",
			secret:      "",
			shouldError: true,
		},
	}

	logger := logrus.New()
	options := Options{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter, err := NewExporter(tt.uri, tt.secret, logger, options)
			if tt.shouldError {
				assert.Error(t, err)
				assert.Nil(t, exporter)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, exporter)
			}
		})
	}
}

func setupTestServer(t *testing.T, endpoint string, response interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-secret", r.Header.Get("secret"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
}

func TestExtractVersion(t *testing.T) {
	mockResponse := ZLMAPIResponse[APIVersionObject]{
		Code: 0,
		Msg:  "success",
		Data: APIVersionObject{
			BranchName: "master",
			BuildTime:  "20220101",
			CommitHash: "abc123",
		},
	}

	server := setupTestServer(t, ZlmAPIEndpointVersion, mockResponse)
	defer server.Close()

	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter(server.URL, MockZlmServerSecret, logger, options)
	assert.NoError(t, err)

	ch := make(chan prometheus.Metric, 1)
	done := make(chan bool)

	go func() {
		exporter.extractVersion(ch)
		close(ch)
		done <- true
	}()

	metrics := make([]prometheus.Metric, 0)
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	<-done

	assert.Equal(t, 1, len(metrics))
}

func TestExtractAPIStatus(t *testing.T) {
	mockResponse := ZLMAPIResponse[[]string]{
		Code: 0,
		Msg:  "success",
		Data: []string{
			"index/api/version",
			"index/api/getApiList",
		},
	}

	server := setupTestServer(t, ZlmAPIEndpointGetApiList, mockResponse)
	defer server.Close()

	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter(server.URL, MockZlmServerSecret, logger, options)
	assert.NoError(t, err)

	ch := make(chan prometheus.Metric, 2)
	done := make(chan bool)

	go func() {
		exporter.extractAPIStatus(ch)
		close(ch)
		done <- true
	}()

	metrics := make([]prometheus.Metric, 0)
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	<-done

	assert.Equal(t, 2, len(metrics))
}

func TestExtractNetworkThreads(t *testing.T) {
	mockResponse := ZLMAPIResponse[APINetworkThreadsObjects]{
		Code: 0,
		Msg:  "success",
		Data: APINetworkThreadsObjects{
			APINetworkThreadsObject{
				Load:  100,
				Delay: 100,
			},
			APINetworkThreadsObject{
				Load:  200,
				Delay: 200,
			},
		},
	}
	server := setupTestServer(t, ZlmAPIEndpointGetNetworkThreads, mockResponse)
	defer server.Close()

	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter(server.URL, MockZlmServerSecret, logger, options)
	assert.NoError(t, err)

	ch := make(chan prometheus.Metric, 1)
	done := make(chan bool)

	go func() {
		exporter.extractNetworkThreads(ch)
		close(ch)
		done <- true
	}()

	metrics := make([]prometheus.Metric, 0)
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	<-done

	assert.Equal(t, 3, len(metrics))
}

func TestExtractWorkThreads(t *testing.T) {
	mockResponse := ZLMAPIResponse[APIWorkThreadsObjects]{
		Code: 0,
		Msg:  "success",
		Data: APIWorkThreadsObjects{
			APIWorkThreadsObject{
				Load:  100,
				Delay: 100,
			},
			APIWorkThreadsObject{
				Load:  200,
				Delay: 200,
			},
		},
	}
	server := setupTestServer(t, ZlmAPIEndpointGetWorkThreads, mockResponse)
	defer server.Close()

	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter(server.URL, MockZlmServerSecret, logger, options)
	assert.NoError(t, err)

	ch := make(chan prometheus.Metric, 1)
	done := make(chan bool)

	go func() {
		exporter.extractWorkThreads(ch)
		close(ch)
		done <- true
	}()

	metrics := make([]prometheus.Metric, 0)
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	<-done

	assert.Equal(t, 3, len(metrics))
}

func TestExtractStatistics(t *testing.T) {
	mockResponse := ZLMAPIResponse[APIStatisticsObject]{
		Code: 0,
		Msg:  "success",
		Data: APIStatisticsObject{
			Buffer:                100,
			BufferLikeString:      100,
			BufferList:            100,
			BufferRaw:             100,
			Frame:                 100,
			FrameImp:              100,
			MediaSource:           100,
			MultiMediaSourceMuxer: 100,
			RtmpPacket:            100,
			RtpPacket:             100,
			Socket:                100,
			TcpClient:             100,
			TcpServer:             100,
			TcpSession:            100,
			UdpServer:             100,
			UdpSession:            100,
		},
	}
	server := setupTestServer(t, ZlmAPIEndpointGetStatistics, mockResponse)
	defer server.Close()

	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter(server.URL, MockZlmServerSecret, logger, options)
	assert.NoError(t, err)

	ch := make(chan prometheus.Metric, 1)
	done := make(chan bool)

	go func() {
		exporter.extractStatistics(ch)
		close(ch)
		done <- true
	}()

	metrics := make([]prometheus.Metric, 0)
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	<-done

	assert.Equal(t, 16, len(metrics))
}

func TestExtractSession(t *testing.T) {
	mockResponse := ZLMAPIResponse[APISessionObjects]{
		Code: 0,
		Msg:  "success",
		Data: APISessionObjects{
			APISessionObject{
				Id:         "1111",
				Identifier: "1111",
				LocalIp:    "127.0.0.1",
				LocalPort:  1111,
				PeerIp:     "127.0.0.1",
				PeerPort:   1111,
				TypeID:     "1111",
			},
			APISessionObject{
				Id:         "2222",
				Identifier: "2222",
				LocalIp:    "127.0.0.1",
				LocalPort:  2222,
				PeerIp:     "127.0.0.1",
				PeerPort:   2222,
				TypeID:     "2222",
			},
		},
	}
	server := setupTestServer(t, ZlmAPIEndpointGetAllSession, mockResponse)
	defer server.Close()

	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter(server.URL, MockZlmServerSecret, logger, options)
	assert.NoError(t, err)

	ch := make(chan prometheus.Metric, 1)
	done := make(chan bool)

	go func() {
		exporter.extractSession(ch)
		close(ch)
		done <- true
	}()

	metrics := make([]prometheus.Metric, 0)
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	<-done

	assert.Equal(t, 3, len(metrics))
}

func TestExtractStreamInfo(t *testing.T) {
	mockResponse := ZLMAPIResponse[APIStreamInfoObjects]{
		Code: 0,
		Msg:  "success",
		Data: APIStreamInfoObjects{
			APIStreamInfoObject{
				Stream:           "test1",
				Vhost:            "test1",
				App:              "test1",
				Schema:           "test1",
				AliveSecond:      100,
				BytesSpeed:       100,
				OriginType:       100,
				OriginTypeStr:    "test1",
				OriginUrl:        "test1",
				ReaderCount:      100,
				TotalReaderCount: 100,
			},
			APIStreamInfoObject{
				Stream:           "test2",
				Vhost:            "test2",
				App:              "test2",
				Schema:           "test2",
				AliveSecond:      200,
				BytesSpeed:       200,
				OriginType:       200,
				OriginTypeStr:    "test2",
				OriginUrl:        "test2",
				ReaderCount:      200,
				TotalReaderCount: 200,
			},
		},
	}
	server := setupTestServer(t, ZlmAPIEndpointGetStream, mockResponse)
	defer server.Close()

	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter(server.URL, MockZlmServerSecret, logger, options)
	assert.NoError(t, err)

	ch := make(chan prometheus.Metric, 1)
	done := make(chan bool)

	go func() {
		exporter.extractStream(ch)
		close(ch)
		done <- true
	}()

	metrics := make([]prometheus.Metric, 0)
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	<-done

	assert.Equal(t, 10, len(metrics))
}

func TestExtractRtpServer(t *testing.T) {
	mockResponse := ZLMAPIResponse[APIRtpServerObjects]{
		Code: 0,
		Msg:  "success",
		Data: APIRtpServerObjects{
			APIRtpServerObject{
				Port:     "1111",
				StreamID: "1111",
			},
			APIRtpServerObject{
				Port:     "2222",
				StreamID: "2222",
			},
		},
	}
	server := setupTestServer(t, ZlmAPIEndpointListRtpServer, mockResponse)
	defer server.Close()

	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter(server.URL, MockZlmServerSecret, logger, options)
	assert.NoError(t, err)

	ch := make(chan prometheus.Metric, 1)
	done := make(chan bool)

	go func() {
		exporter.extractRtp(ch)
		close(ch)
		done <- true
	}()

	metrics := make([]prometheus.Metric, 0)
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	<-done

	assert.Equal(t, 3, len(metrics))
}

func TestMustNewConstMetric(t *testing.T) {
	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter("http://localhost", MockZlmServerSecret, logger, options)
	assert.NoError(t, err)

	tests := []struct {
		name        string
		value       interface{}
		shouldBeNil bool
	}{
		{
			name:        "float64",
			value:       float64(123.45),
			shouldBeNil: false,
		},
		{
			name:        "string",
			value:       "123.45",
			shouldBeNil: false,
		},
		{
			name:        "non-numeric string",
			value:       "abc",
			shouldBeNil: false,
		},
		{
			name:        "other type",
			value:       struct{}{},
			shouldBeNil: true,
		},
	}

	desc := prometheus.NewDesc("test_metric", "Test metric", []string{"label"}, nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metric := exporter.mustNewConstMetric(desc, prometheus.GaugeValue, tt.value, "test_label")
			if tt.shouldBeNil {
				assert.Nil(t, metric)
			} else {
				assert.NotNil(t, metric)
			}
		})
	}
}

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultVal   string
		envValue     string
		expectedVal  string
		shouldSetEnv bool
	}{
		{
			name:         "env exists",
			key:          "TEST_ENV_1",
			defaultVal:   "default",
			envValue:     "custom",
			expectedVal:  "custom",
			shouldSetEnv: true,
		},
		{
			name:         "env not exists",
			key:          "TEST_ENV_2",
			defaultVal:   "default",
			expectedVal:  "default",
			shouldSetEnv: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldSetEnv {
				t.Setenv(tt.key, tt.envValue)
			}
			result := getEnv(tt.key, tt.defaultVal)
			assert.Equal(t, tt.expectedVal, result)
		})
	}
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultVal   bool
		envValue     string
		expectedVal  bool
		shouldSetEnv bool
	}{
		{
			name:         "valid true",
			key:          "TEST_BOOL_1",
			defaultVal:   false,
			envValue:     "true",
			expectedVal:  true,
			shouldSetEnv: true,
		},
		{
			name:         "valid false",
			key:          "TEST_BOOL_2",
			defaultVal:   true,
			envValue:     "false",
			expectedVal:  false,
			shouldSetEnv: true,
		},
		{
			name:         "invalid bool",
			key:          "TEST_BOOL_3",
			defaultVal:   true,
			envValue:     "invalid",
			expectedVal:  true,
			shouldSetEnv: true,
		},
		{
			name:         "env not exists",
			key:          "TEST_BOOL_4",
			defaultVal:   true,
			expectedVal:  true,
			shouldSetEnv: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldSetEnv {
				t.Setenv(tt.key, tt.envValue)
			}
			result := getEnvBool(tt.key, tt.defaultVal)
			assert.Equal(t, tt.expectedVal, result)
		})
	}
}

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name      string
		logFormat string
		logLevel  string
		wantErr   bool
		checkFunc func(*logrus.Logger) bool
	}{
		{
			name:      "default txt format and info level",
			logFormat: "txt",
			logLevel:  "info",
			wantErr:   false,
			checkFunc: func(l *logrus.Logger) bool {
				_, isTxt := l.Formatter.(*logrus.TextFormatter)
				return isTxt && l.Level == logrus.InfoLevel
			},
		},
		{
			name:      "json format and debug level",
			logFormat: "json",
			logLevel:  "debug",
			wantErr:   false,
			checkFunc: func(l *logrus.Logger) bool {
				_, isJSON := l.Formatter.(*logrus.JSONFormatter)
				return isJSON && l.Level == logrus.DebugLevel
			},
		},
		{
			name:      "unknown format default use txt format",
			logFormat: "unknown",
			logLevel:  "info",
			wantErr:   false,
			checkFunc: func(l *logrus.Logger) bool {
				_, isTxt := l.Formatter.(*logrus.TextFormatter)
				return isTxt && l.Level == logrus.InfoLevel
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					if !tt.wantErr {
						t.Errorf("unexpected panic: %v", r)
					}
				}
			}()

			logger := newLogger(tt.logFormat, tt.logLevel)

			if tt.wantErr {
				t.Error("newLogger() should return error")
				return
			}

			if logger == nil {
				t.Error("newLogger() returned nil")
				return
			}

			if !tt.checkFunc(logger) {
				t.Error("newLogger() config not match expected")
			}
		})
	}
}
