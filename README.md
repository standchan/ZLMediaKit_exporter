# zlm_exporter

![zlm_exporter](https://socialify.git.ci/standchan/zlm_exporter/image?language=1&owner=1&name=1&stargazers=1&theme=Light)

Prometheus exporter for [ZLMediaKit](https://github.com/ZLMediaKit/ZLMediaKit) metrics, written in Go.

[![](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/standchan/zlm_exporter/blob/master/LICENSE)
[![](https://img.shields.io/badge/language-golang-red.svg)](https://en.cppreference.com/)
[![](https://img.shields.io/badge/PRs-welcome-yellow.svg)](https://github.com/standchan/zlm_exporter/pulls)

## Installation

### Docker
```shell
docker pull standchan/zlm_exporter
# OR
docker build -t zlm_exporter:latest .

# Run
docker run -d --name zlm_exporter -p 9101:9101 zlm_exporter:latest

```
### Source
```shell
git clone https://github.com/standchan/zlm_exporter
cd zlm_exporter
go build
```

## Environment Variables


|  Name                      | Description                               | default  |
|-------------------------   |-------------------------------------------|----------|
| `ZLM_API_URI`  | URI on which to scrape zlmediakit metrics(ZlMediaKit apiServer url).       |  http://localhost  |
| `ZLM_API_SECRET`      | Secret for the scrape URI            |        |
| `ZLM_EXPORTER_WEB_TELEMETRY_ADDRESS`| Address to expose metrics. |  :9101 |
| `ZLM_EXPORTER_WEB_TELEMETRY_PATH`| Path under which to expose metrics. |  /metrics |
| `ZLM_EXPORTER_SSL_VERIFY` | Skip TLS verification | false |

## Metrics

| Metric Name                               | Labels                          | Description                      |
|-------------------------------------------|---------------------------------|----------------------------------|
| `zlm_version_info`                        | branchName、buildTime、commitHash | Version info of ZLMediakit       |
| `zlm_api_status`                          | endpoint                        | The status of API endpoint       |
| `zlm_network_threads_total`               | {}                                | Total number of network threads  |
| `zlm_network_threads_load_total`          | {}                                | Total of network threads load    |
| `zlm_network_threads_delay_total`         | {}                                | Total of network threads delay   |
| `zlm_work_threads_total`                  | {}                                | Total number of work threads     |
| `zlm_work_threads_load_total`             | {}                                | Total of work threads load       |
| `zlm_work_threads_delay_total`            | {}                                | Total of work threads delay      |
| `zlm_statistics_buffer`                   | {}                                | Statistics buffer                |
| `zlm_statistics_buffer_like_string`       | {}                                | Statistics BufferLikeString      |
| `zlm_statistics_buffer_list`              | {}                                | Statistics BufferList            |
| `zlm_statistics_buffer_raw`               | {}                                | Statistics BufferRaw             |
| `zlm_statistics_frame`                    | {}                                | Statistics Frame                 |
| `zlm_statistics_frame_imp`                | {}                                | Statistics FrameImp              |
| `zlm_statistics_media_source`             | {}                                | Statistics MediaSource           |
| `zlm_statistics_multi_media_source_muxer` | {}                                | Statistics MultiMediaSourceMuxer |
| `zlm_statistics_rtp_packet`               | {}                                | Statistics RtpPacket             |
| `zlm_statistics_socket`                   | {}                                | Statistics Socket                |
| `zlm_statistics_tcp_client`               | {}                                | Statistics TcpClient             |
| `zlm_statistics_tcp_server`               | {}                                | Statistics TcpServer             |
| `zlm_statistics_tcp_session`              | {}                                | Statistics TcpSession            |
| `zlm_statistics_udp_server`               | {}                                | Statistics UdpServer             |
| `zlm_statistics_udp_session`              | {}                                | Statistics UdpSession            |

## Contributing and reporting issues

JUST DO IT! 

We are happy to receive your feedback and contributions.


## Thanks
[ZLMediaKit](https://github.com/ZLMediaKit/ZLMediaKit)

[JetBrains](https://www.jetbrains.com/)

[redis_exporter](https://github.com/oliver006/redis_exporter)

[haproxy_exporter](https://github.com/prometheus/haproxy_exporter)

[Prometheus](https://prometheus.io/)

[Cursor](https://www.cursor.com/)

JetBrains/Cursor provides great IDE for coding.

Most unittest powered by Cursor.