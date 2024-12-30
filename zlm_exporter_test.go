package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/gin-gonic/gin"
)

var (
	MockZlmServerPort    = "9999"
	MockZlmServerAddr    = fmt.Sprintf("http://localhost:%s", MockZlmServerPort)
	MockZlmServerSecret  = "test"
	MockZlmServerHandler = gin.Default()
	TestServerHandler    = gin.Default()
	TestServerAddr       = ":9999"
	TestServerSecret     = "test-secret"
)

var (
	TestClientCertFile = "testdata/tls/client-cert.pem"
	TestClientKeyFile  = "testdata/tls/client-key.pem"
	TestCaCertFile     = "testdata/tls/ca-cert.pem"
	TestServerCertFile = "testdata/tls/server-cert.pem"
	TestServerKeyFile  = "testdata/tls/server-key.pem"
	TestTLSVersion     = "TLS1.2"
)

func setup() {
	setupTLSTestFile()
	setupZlmApiServer()
}

func setupZlmApiServer() {
	r := TestServerHandler
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

	r.Run(TestServerAddr)
}

func setupTLSTestFile() {
	scriptPath := "scripts/generate-test-certs.sh"
	cmd := exec.Command("/bin/bash", scriptPath)
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
}

func readTestData(name string) map[string]any {
	file, err := os.ReadFile(fmt.Sprintf("%s.json", name))
	if err != nil {
		log.Fatal(err)
	}
	var fileJson map[string]any
	json.Unmarshal(file, &fileJson)
	return fileJson
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

func TestServerTLSConfig(t *testing.T) {
	setupTLSTestFile()
	defer tearDown()
	logger := logrus.New()
	options := Options{
		SkipTLSVerification: false,
		ClientCertFile:      TestClientCertFile,
		ClientKeyFile:       TestClientKeyFile,
		CaCertFile:          TestCaCertFile,
	}

	exporter, err := NewExporter(TestServerAddr, TestServerSecret, logger, options)
	assert.NoError(t, err)

	tlsConfig := exporter.CreateClientTLSConfig()
	assert.NotNil(t, tlsConfig)
	assert.False(t, tlsConfig.InsecureSkipVerify)

	serverTLSConfig, err := exporter.CreateServerTLSConfig(
		TestServerCertFile,
		TestServerKeyFile,
		TestCaCertFile,
		TestTLSVersion,
	)
	assert.NoError(t, err)
	assert.NotNil(t, serverTLSConfig)

}

func TestGetServerCertificateFunc(t *testing.T) {
	setupTLSTestFile()
	defer tearDown()
	certFunc := GetServerCertificateFunc(TestServerCertFile, TestServerKeyFile)
	assert.NotNil(t, certFunc)
	cert, err := certFunc(nil)
	assert.NoError(t, err)
	assert.NotNil(t, cert)
}

func TestGetConfigForClientFunc(t *testing.T) {
	setupTLSTestFile()
	defer tearDown()
	configFunc := GetConfigForClientFunc(
		TestServerCertFile,
		TestServerKeyFile,
		TestCaCertFile,
	)
	assert.NotNil(t, configFunc)
	config, err := configFunc(nil)
	assert.NoError(t, err)
	assert.NotNil(t, config)
}

func TestLoadKeyPair(t *testing.T) {
	_, err := LoadKeyPair("invalid-cert.pem", "invalid-key.pem")
	assert.Error(t, err)
}

func TestLoadCAFile(t *testing.T) {
	_, err := LoadCAFile("invalid-ca.pem")
	assert.Error(t, err)
}

func TestServer(t *testing.T) {
	setupZlmApiServer()
	// 测试整个流程
	main()
	defer tearDown()
}

func tearDown() {
	os.RemoveAll("testdata/tls")
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
			secret:      "test-secret",
			shouldError: false,
		},
		{
			name:        "空URI",
			uri:         "",
			secret:      "test-secret",
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

func TestCreateClientTLSConfig(t *testing.T) {
	logger := logrus.New()
	options := Options{
		SkipTLSVerification: true,
	}

	exporter, err := NewExporter("http://localhost:8080", "test-secret", logger, options)
	assert.NoError(t, err)

	tlsConfig := exporter.CreateClientTLSConfig()
	assert.True(t, tlsConfig.InsecureSkipVerify)
}

func setupTestServer(t *testing.T, endpoint string, response interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 验证请求头中的secret
		assert.Equal(t, "test-secret", r.Header.Get("secret"))

		// 返回模拟响应
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
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

	server := setupTestServer(t, "index/api/version", mockResponse)
	defer server.Close()

	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter(server.URL, "test-secret", logger, options)
	assert.NoError(t, err)

	// 创建一个通道来接收指标
	ch := make(chan prometheus.Metric, 1)
	done := make(chan bool)

	go func() {
		exporter.extractVersion(ch)
		close(ch)
		done <- true
	}()

	// 验证收到的指标
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

	server := setupTestServer(t, "index/api/getApiList", mockResponse)
	defer server.Close()

	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter(server.URL, "test-secret", logger, options)
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
		Data: APINetworkThreadsObjects{},
	}
	server := setupTestServer(t, "index/api/getThreadsLoad", mockResponse)
	defer server.Close()

	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter(server.URL, "test-secret", logger, options)
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

	assert.Equal(t, 1, len(metrics))
}

func TestExtractWorkThreads(t *testing.T) {
	mockResponse := ZLMAPIResponse[APIWorkThreadsObjects]{
		Code: 0,
		Msg:  "success",
		Data: APIWorkThreadsObjects{},
	}
	server := setupTestServer(t, "index/api/getWorkThreadsLoad", mockResponse)
	defer server.Close()

	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter(server.URL, "test-secret", logger, options)
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

	assert.Equal(t, 1, len(metrics))
}

func TestExtractStatistics(t *testing.T) {
	mockResponse := ZLMAPIResponse[APIStatisticsObject]{
		Code: 0,
		Msg:  "success",
		Data: APIStatisticsObject{},
	}
	server := setupTestServer(t, "index/api/getStatistic", mockResponse)
	defer server.Close()

	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter(server.URL, "test-secret", logger, options)
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

	assert.Equal(t, 1, len(metrics))
}

func TestExtractSession(t *testing.T) {
	mockResponse := ZLMAPIResponse[APISessionObjects]{
		Code: 0,
		Msg:  "success",
		Data: APISessionObjects{},
	}
	server := setupTestServer(t, "index/api/getAllSession", mockResponse)
	defer server.Close()

	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter(server.URL, "test-secret", logger, options)
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

	assert.Equal(t, 1, len(metrics))
}

func TestExtractStreamInfo(t *testing.T) {
	mockResponse := ZLMAPIResponse[APIStreamInfoObjects]{
		Code: 0,
		Msg:  "success",
		Data: APIStreamInfoObjects{},
	}
	server := setupTestServer(t, "index/api/getMediaList", mockResponse)
	defer server.Close()

	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter(server.URL, "test-secret", logger, options)
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

	assert.Equal(t, 1, len(metrics))
}

func TestExtractRtpServer(t *testing.T) {
	mockResponse := ZLMAPIResponse[APIRtpServerObjects]{
		Code: 0,
		Msg:  "success",
		Data: APIRtpServerObjects{},
	}
	server := setupTestServer(t, "index/api/listRtpServer", mockResponse)
	defer server.Close()

	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter(server.URL, "test-secret", logger, options)
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

	assert.Equal(t, 1, len(metrics))
}

func TestMustNewConstMetric(t *testing.T) {
	logger := logrus.New()
	options := Options{}
	exporter, err := NewExporter("http://localhost", "test-secret", logger, options)
	assert.NoError(t, err)

	tests := []struct {
		name        string
		value       interface{}
		shouldBeNil bool
	}{
		{
			name:        "float64值",
			value:       float64(123.45),
			shouldBeNil: false,
		},
		{
			name:        "字符串数字",
			value:       "123.45",
			shouldBeNil: false,
		},
		{
			name:        "非数字字符串",
			value:       "abc",
			shouldBeNil: false,
		},
		{
			name:        "其他类型",
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
			name:         "环境变量存在",
			key:          "TEST_ENV_1",
			defaultVal:   "default",
			envValue:     "custom",
			expectedVal:  "custom",
			shouldSetEnv: true,
		},
		{
			name:         "环境变量不存在",
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
			name:         "有效的true值",
			key:          "TEST_BOOL_1",
			defaultVal:   false,
			envValue:     "true",
			expectedVal:  true,
			shouldSetEnv: true,
		},
		{
			name:         "有效的false值",
			key:          "TEST_BOOL_2",
			defaultVal:   true,
			envValue:     "false",
			expectedVal:  false,
			shouldSetEnv: true,
		},
		{
			name:         "无效的布尔值",
			key:          "TEST_BOOL_3",
			defaultVal:   true,
			envValue:     "invalid",
			expectedVal:  true,
			shouldSetEnv: true,
		},
		{
			name:         "环境变量不存在",
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
