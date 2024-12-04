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
	// 构建一个 zlmediakit echo server,用来提供 metrics 数据
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
			name:       "环境变量存在",
			key:        "TEST_KEY",
			defaultVal: "default",
			envVal:     "test_value",
			want:       "test_value",
		},
		{
			name:       "环境变量不存在",
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
			name:       "环境变量为true",
			key:        "TEST_BOOL",
			defaultVal: false,
			envVal:     "true",
			want:       true,
		},
		{
			name:       "环境变量为false",
			key:        "TEST_BOOL",
			defaultVal: true,
			envVal:     "false",
			want:       false,
		},
		{
			name:       "环境变量不存在",
			key:        "NON_EXISTENT_BOOL",
			defaultVal: true,
			envVal:     "",
			want:       true,
		},
		{
			name:       "环境变量格式错误",
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

func TestNewMetricDescr(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		metric    string
		doc       string
		labels    []string
		want      string
	}{
		{
			name:      "基本指标测试",
			namespace: "test",
			metric:    "metric_name",
			doc:       "Test metric",
			labels:    []string{"label1", "label2"},
			want:      "test_metric_name",
		},
		{
			name:      "空标签测试",
			namespace: "test",
			metric:    "metric_name",
			doc:       "Test metric",
			labels:    []string{},
			want:      "test_metric_name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newMetricDescr(tt.namespace, tt.metric, tt.doc, tt.labels)
			fmt.Println(got.String())
			if got == nil {
				t.Error("newMetricDescr() returned nil")
			}
			if got.String() != tt.want {
				t.Errorf("newMetricDescr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMetricsRegistration(t *testing.T) {
	// 验证所有预定义的指标是否正确注册
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
}

func TestMetricsSlice(t *testing.T) {
	// 验证metrics切片是否正确存储了所有指标
	expectedMetrics := 4 // 当前定义的指标数量
	if len(metrics) != expectedMetrics {
		t.Errorf("Expected %d metrics, got %d", expectedMetrics, len(metrics))
	}
}

func TestServerStartupAndShutdown(t *testing.T) {
	// 创建测试用 logger
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// 创建测试用 exporter
	options := Options{
		ScrapeURI: "http://localhost:8080",
	}
	exporter, err := NewExporter(logger, options)
	assert.NoError(t, err)
	assert.NotNil(t, exporter)

	// 创建测试服务器
	srv := &http.Server{
		Addr: ":9999", // 使用测试端口
	}

	// 启动服务器
	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			t.Errorf("预期外的服务器错误: %v", err)
		}
	}()

	// 等待服务器启动
	time.Sleep(100 * time.Millisecond)

	// 测试服务器是否正在运行
	_, err = http.Get("http://localhost:9999")
	assert.NoError(t, err)

	// 测试优雅关闭
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = srv.Shutdown(ctx)
	assert.NoError(t, err)

	// 验证服务器已关闭
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

	// 测试 TLS 配置创建
	tlsConfig := exporter.CreateClientTLSConfig()
	assert.NotNil(t, tlsConfig)
	assert.False(t, tlsConfig.InsecureSkipVerify)

	// 测试服务器 TLS 配置
	serverTLSConfig, err := exporter.CreateServerTLSConfig(
		"test/server-cert.pem",
		"test/server-key.pem",
		"test/ca-cert.pem",
		"TLS1.2",
	)
	assert.NoError(t, err)
	assert.NotNil(t, serverTLSConfig)
}

func TestGetServerCertificateFunc(t *testing.T) {
	certFunc := GetServerCertificateFunc("test/server-cert.pem", "test/server-key.pem")
	assert.NotNil(t, certFunc)

	// 注意：这里我们不测试实际的证书加载，因为测试文件可能不存在
	// 实际项目中应该提供测试证书文件
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
	// 测试无效的证书文件
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
