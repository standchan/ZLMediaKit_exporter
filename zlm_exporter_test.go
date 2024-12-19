package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/gin-gonic/gin"
)

func setup(t *testing.T) {
	r := gin.Default()
	r.GET("index/api/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, readTestData("version"))
	})

	r.GET("index/api/getApiList", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"code": 0, "data": []string{"api1", "api2"}})
	})

	r.GET("index/api/getThreadsLoad", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"code": 0, "data": 0.1})
	})

	r.GET("index/api/getWorkThreadsLoad", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"code": 0, "data": 0.2})
	})

	r.GET("index/api/getStatistic", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"code": 0, "data": gin.H{"total_bytes": 1024}})
	})

	r.GET("index/api/getServerConfig", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"code": 0, "data": gin.H{"server": "test_server"}})
	})

	r.GET("index/api/getAllSession", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"code": 0, "data": gin.H{"total": 10}})
	})

	r.GET("index/api/getMediaList", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"code": 0, "data": gin.H{"total": 10}})
	})

	r.GET("index/api/listRtpServer", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"code": 0, "data": gin.H{"total": 10}})
	})

	r.Run(":80")
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

func TestServerStartupAndShutdown(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	options := Options{
		ScrapeURI: "http://localhost:8080",
	}
	exporter, err := NewExporter(logger, options)
	assert.NoError(t, err)
	assert.NotNil(t, exporter)

	srv := &http.Server{
		Addr: ":9999",
	}

	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			t.Errorf("预期外的服务器错误: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	_, err = http.Get("http://localhost:9999")
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = srv.Shutdown(ctx)
	assert.NoError(t, err)

	_, err = http.Get("http://localhost:9999")
	assert.Error(t, err)
}

func TestServerTLSConfig(t *testing.T) {
	logger := logrus.New()
	options := Options{
		ScrapeURI:      "https://localhost:8080",
		ClientCertFile: "test/client-cert.pem",
		ClientKeyFile:  "test/client-key.pem",
		CaCertFile:     "test/ca-cert.pem",
	}

	exporter, err := NewExporter(logger, options)
	assert.NoError(t, err)

	tlsConfig := exporter.CreateClientTLSConfig()
	assert.NotNil(t, tlsConfig)
	assert.False(t, tlsConfig.InsecureSkipVerify)

	serverTLSConfig, err := exporter.CreateServerTLSConfig(
		"testdata/tls/server-cert.pem",
		"testdata/tls/server-key.pem",
		"testdata/tls/ca-cert.pem",
		"TLS1.2",
	)
	assert.NoError(t, err)
	assert.NotNil(t, serverTLSConfig)
}

func TestGetServerCertificateFunc(t *testing.T) {
	certFunc := GetServerCertificateFunc("test/server-cert.pem", "test/server-key.pem")
	assert.NotNil(t, certFunc)
}

func TestGetConfigForClientFunc(t *testing.T) {
	configFunc := GetConfigForClientFunc(
		"test/server-cert.pem",
		"test/server-key.pem",
		"test/ca-cert.pem",
	)
	assert.NotNil(t, configFunc)

	// 注意：这里我们不测试实际的配置加载，因为测试文件可能不存在
	// 实际项目中应该提供测试证书文件
}

func TestLoadKeyPair(t *testing.T) {
	_, err := LoadKeyPair("invalid-cert.pem", "invalid-key.pem")
	assert.Error(t, err)

	// 注意：实际项目中应该提供有效的测试证书文件进行测试
}

func TestLoadCAFile(t *testing.T) {
	// 测试无效的 CA 文件
	_, err := LoadCAFile("invalid-ca.pem")
	assert.Error(t, err)

	// 注意：实际项目中应该提供有效的测试 CA 文件进行测试
}

func tearDown() {
	os.RemoveAll("testdata/tls")
}
