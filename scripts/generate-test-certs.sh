#!/bin/bash

set -e

mkdir -p testdata/tls
cd testdata/tls

echo "开始生成测试证书..."

echo "1. 生成 CA 证书..."
openssl genrsa -out ca-key.pem 2048
openssl req -x509 -new -nodes \
  -key ca-key.pem \
  -sha256 \
  -days 3650 \
  -out ca-cert.pem \
  -subj "/CN=Test CA"

# 生成服务器证书
echo "2. 生成服务器证书..."
openssl genrsa -out server-key.pem 2048
openssl req -new \
  -key server-key.pem \
  -out server.csr \
  -subj "/CN=localhost"

# 创建服务器证书扩展配置文件
cat > server-ext.cnf << EOF
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

# 使用 CA 证书签名服务器证书
openssl x509 -req \
  -in server.csr \
  -CA ca-cert.pem \
  -CAkey ca-key.pem \
  -CAcreateserial \
  -out server-cert.pem \
  -days 365 \
  -extfile server-ext.cnf

# 生成客户端证书
echo "3. 生成客户端证书..."
openssl genrsa -out client-key.pem 2048
openssl req -new \
  -key client-key.pem \
  -out client.csr \
  -subj "/CN=test-client"

# 使用 CA 证书签名客户端证书
openssl x509 -req \
  -in client.csr \
  -CA ca-cert.pem \
  -CAkey ca-key.pem \
  -CAcreateserial \
  -out client-cert.pem \
  -days 365

# 清理临时文件
echo "4. 清理临时文件..."
rm -f *.csr server-ext.cnf *.srl

# 设置适当的文件权限
chmod 644 *.pem

echo "5. 验证生成的证书..."
# 验证服务器证书
openssl verify -CAfile ca-cert.pem server-cert.pem
# 验证客户端证书
openssl verify -CAfile ca-cert.pem client-cert.pem

echo "证书生成完成！生成的文件："
ls -l

echo "
生成的文件说明：
- ca-cert.pem：CA 证书
- ca-key.pem：CA 私钥
- server-cert.pem：服务器证书
- server-key.pem：服务器私钥
- client-cert.pem：客户端证书
- client-key.pem：客户端私钥
"

cd ../..
