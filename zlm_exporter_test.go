package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/gin-gonic/gin"
)

var (
	MockZlmServerPort    = "9999"
	MockZlmServerAddr    = fmt.Sprintf("http://localhost:%s", MockZlmServerPort)
	MockZlmServerSecret  = "test"
	MockZlmServerHandler = gin.Default()
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

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		defaultVal string
		envVal     string
		want       string
	}{
		{
			name:       "env is set",
			key:        "TEST_KEY",
			defaultVal: "default",
			envVal:     "test_value",
			want:       "test_value",
		},
		{
			name:       "env is not set",
			key:        "NON_EXISTENT_KEY",
			defaultVal: "default",
			envVal:     "",
			want:       "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVal != "" {
				os.Setenv(tt.key, tt.envVal)
				defer os.Unsetenv(tt.key)
			}

			if got := getEnv(tt.key, tt.defaultVal); got != tt.want {
				t.Errorf("getEnv() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		defaultVal bool
		envVal     string
		want       bool
	}{
		{
			name:       "env is true",
			key:        "TEST_BOOL",
			defaultVal: false,
			envVal:     "true",
			want:       true,
		},
		{
			name:       "env is false",
			key:        "TEST_BOOL",
			defaultVal: true,
			envVal:     "false",
			want:       false,
		},
		{
			name:       "env is not set",
			key:        "NON_EXISTENT_BOOL",
			defaultVal: true,
			envVal:     "",
			want:       true,
		},
		{
			name:       "env is invalid",
			key:        "INVALID_BOOL",
			defaultVal: true,
			envVal:     "invalid",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVal != "" {
				os.Setenv(tt.key, tt.envVal)
				defer os.Unsetenv(tt.key)
			}

			if got := getEnvBool(tt.key, tt.defaultVal); got != tt.want {
				t.Errorf("getEnvBool() = %v, want %v", got, tt.want)
			}
		})
	}
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
