# zlm_exporter

![zlm_exporter](https://socialify.git.ci/standchan/zlm_exporter/image?language=1&owner=1&name=1&stargazers=1&theme=Light)

Prometheus exporter for [ZLMediaKit](https://github.com/ZLMediaKit/ZLMediaKit) metrics, written in Go.

[![](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/standchan/zlm_exporter/blob/master/LICENSE)
[![](https://img.shields.io/badge/language-golang-red.svg)](https://en.cppreference.com/)
[![](https://img.shields.io/badge/PRs-welcome-yellow.svg)](https://github.com/standchan/zlm_exporter/pulls)

## NOTE
⚠️ Not production-ready. Please thoroughly test before deploying to production environments.


## Usage

### Docker

TODO

### Source
```shell
git clone https://github.com/standchan/zlm_exporter
cd zlm_exporter
make build
./zlm_exporter --zlm.api-url=<zlmediakit_api_uri> --zlm.secret=<zlmediakit_api_secret>
```

## Command line flags

|  Name                      | Environment Variable Name                               | Description  |
|-------------------------   |-------------------------------------------|----------|
| `zlm.api-url`  |  ZLM_API_URL      |  URI on which to scrape zlmediakit metrics(ZlMediaKit apiServer url) default: http://localhost  |
| `zlm.secret`      | ZLM_API_SECRET            | Secret for the scrape URI            |
| `web.listen-address`| ZLM_EXPORTER_TELEMETRY_ADDRESS | Address to expose metrics. default: :9101 |
| `web.telemetry-path`| ZLM_EXPORTER_TELEMETRY_PATH| Path under which to expose metrics. default: /metrics |
| `web.ssl-verify` | ZLM_EXPORTER_SSL_VERIFY | Skip TLS verification. default: true |

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
| `zlm_session_info`                        | id、identifier、local_ip、local_port、peer_ip、peer_port、typeid | Session info                     |
| `zlm_session_total`                       | {}                                | Total number of sessions         |
| `zlm_stream_info`                         | vhost、app、stream、schema、origin_type、origin_url | Stream basic information         |
| `zlm_stream_status`                       | vhost、app、stream、schema         | Stream status (1: active with data flowing, 0: inactive) |
| `zlm_stream_reader_count`                | vhost、app、stream、schema         | Stream reader count              |
| `zlm_stream_total_reader_count`          | vhost、app、stream         | Total reader count across all schemas |
| `zlm_stream_bandwidths`                  | vhost、app、stream、schema、originType         | Stream bandwidth                  |
| `zlm_stream_total`                       | {}                                | Total number of streams         |
| `zlm_rtp_server_info`                    | port、stream_id         | RTP server info                  |
| `zlm_rtp_server_total`                   | {}                                | Total number of RTP servers         |

<details>
<summary>Metrics details Example</summary>
# HELP zlmediakit_api_status The status of API endpoint
# TYPE zlmediakit_api_status gauge
zlmediakit_api_status{endpoint="/index/"} 1
zlmediakit_api_status{endpoint="/index/api/addFFmpegSource"} 1
zlmediakit_api_status{endpoint="/index/api/addStreamProxy"} 1
zlmediakit_api_status{endpoint="/index/api/addStreamPusherProxy"} 1
zlmediakit_api_status{endpoint="/index/api/broadcastMessage"} 1
zlmediakit_api_status{endpoint="/index/api/closeRtpServer"} 1
zlmediakit_api_status{endpoint="/index/api/close_stream"} 1
zlmediakit_api_status{endpoint="/index/api/close_streams"} 1
zlmediakit_api_status{endpoint="/index/api/connectRtpServer"} 1
zlmediakit_api_status{endpoint="/index/api/delFFmpegSource"} 1
zlmediakit_api_status{endpoint="/index/api/delStreamProxy"} 1
zlmediakit_api_status{endpoint="/index/api/delStreamPusherProxy"} 1
zlmediakit_api_status{endpoint="/index/api/deleteRecordDirectory"} 1
zlmediakit_api_status{endpoint="/index/api/downloadBin"} 1
zlmediakit_api_status{endpoint="/index/api/downloadFile"} 1
zlmediakit_api_status{endpoint="/index/api/getAllSession"} 1
zlmediakit_api_status{endpoint="/index/api/getApiList"} 1
zlmediakit_api_status{endpoint="/index/api/getMP4RecordFile"} 1
zlmediakit_api_status{endpoint="/index/api/getMediaInfo"} 1
zlmediakit_api_status{endpoint="/index/api/getMediaList"} 1
zlmediakit_api_status{endpoint="/index/api/getMediaPlayerList"} 1
zlmediakit_api_status{endpoint="/index/api/getProxyInfo"} 1
zlmediakit_api_status{endpoint="/index/api/getProxyPusherInfo"} 1
zlmediakit_api_status{endpoint="/index/api/getRtpInfo"} 1
zlmediakit_api_status{endpoint="/index/api/getServerConfig"} 1
zlmediakit_api_status{endpoint="/index/api/getSnap"} 1
zlmediakit_api_status{endpoint="/index/api/getStatistic"} 1
zlmediakit_api_status{endpoint="/index/api/getThreadsLoad"} 1
zlmediakit_api_status{endpoint="/index/api/getWorkThreadsLoad"} 1
zlmediakit_api_status{endpoint="/index/api/isMediaOnline"} 1
zlmediakit_api_status{endpoint="/index/api/isRecording"} 1
zlmediakit_api_status{endpoint="/index/api/kick_session"} 1
zlmediakit_api_status{endpoint="/index/api/kick_sessions"} 1
zlmediakit_api_status{endpoint="/index/api/listRtpSender"} 1
zlmediakit_api_status{endpoint="/index/api/listRtpServer"} 1
zlmediakit_api_status{endpoint="/index/api/loadMP4File"} 1
zlmediakit_api_status{endpoint="/index/api/openRtpServer"} 1
zlmediakit_api_status{endpoint="/index/api/openRtpServerMultiplex"} 1
zlmediakit_api_status{endpoint="/index/api/pauseRtpCheck"} 1
zlmediakit_api_status{endpoint="/index/api/restartServer"} 1
zlmediakit_api_status{endpoint="/index/api/resumeRtpCheck"} 1
zlmediakit_api_status{endpoint="/index/api/seekRecordStamp"} 1
zlmediakit_api_status{endpoint="/index/api/setRecordSpeed"} 1
zlmediakit_api_status{endpoint="/index/api/setServerConfig"} 1
zlmediakit_api_status{endpoint="/index/api/startRecord"} 1
zlmediakit_api_status{endpoint="/index/api/startSendRtp"} 1
zlmediakit_api_status{endpoint="/index/api/startSendRtpPassive"} 1
zlmediakit_api_status{endpoint="/index/api/stopRecord"} 1
zlmediakit_api_status{endpoint="/index/api/stopSendRtp"} 1
zlmediakit_api_status{endpoint="/index/api/updateRtpServerSSRC"} 1
zlmediakit_api_status{endpoint="/index/api/version"} 1
# HELP zlmediakit_exporter_scrapes_total Current total ZLMediaKit scrapes.
# TYPE zlmediakit_exporter_scrapes_total counter
zlmediakit_exporter_scrapes_total 2
# HELP zlmediakit_network_threads_delay_total Total of network threads delay
# TYPE zlmediakit_network_threads_delay_total gauge
zlmediakit_network_threads_delay_total 1
# HELP zlmediakit_network_threads_load_total Total of network threads load
# TYPE zlmediakit_network_threads_load_total gauge
zlmediakit_network_threads_load_total 0
# HELP zlmediakit_network_threads_total Total number of network threads
# TYPE zlmediakit_network_threads_total gauge
zlmediakit_network_threads_total 8
# HELP zlmediakit_rtp_server_total Total number of RTP servers
# TYPE zlmediakit_rtp_server_total gauge
zlmediakit_rtp_server_total 0
# HELP zlmediakit_session_info Session info
# TYPE zlmediakit_session_info gauge
zlmediakit_session_info{id="11025-84",identifier="11025-84",local_ip="127.0.0.1",local_port="80",peer_ip="127.0.0.1",peer_port="59734",typeid="mediakit::HttpSession"} 1
zlmediakit_session_info{id="11026-79",identifier="11026-79",local_ip="127.0.0.1",local_port="80",peer_ip="127.0.0.1",peer_port="59729",typeid="mediakit::HttpSession"} 1
zlmediakit_session_info{id="11032-77",identifier="11032-77",local_ip="127.0.0.1",local_port="80",peer_ip="127.0.0.1",peer_port="59750",typeid="mediakit::HttpSession"} 1
zlmediakit_session_info{id="11033-78",identifier="11033-78",local_ip="127.0.0.1",local_port="80",peer_ip="127.0.0.1",peer_port="59751",typeid="mediakit::HttpSession"} 1
zlmediakit_session_info{id="11034-81",identifier="11034-81",local_ip="127.0.0.1",local_port="80",peer_ip="127.0.0.1",peer_port="59752",typeid="mediakit::HttpSession"} 1
zlmediakit_session_info{id="11035-80",identifier="11035-80",local_ip="127.0.0.1",local_port="80",peer_ip="127.0.0.1",peer_port="59753",typeid="mediakit::HttpSession"} 1
zlmediakit_session_info{id="11036-82",identifier="11036-82",local_ip="127.0.0.1",local_port="80",peer_ip="127.0.0.1",peer_port="59754",typeid="mediakit::HttpSession"} 1
# HELP zlmediakit_session_total Total number of sessions
# TYPE zlmediakit_session_total gauge
zlmediakit_session_total 7
# HELP zlmediakit_statistics_buffer Statistics buffer
# TYPE zlmediakit_statistics_buffer gauge
zlmediakit_statistics_buffer 11
# HELP zlmediakit_statistics_buffer_like_string Statistics BufferLikeString
# TYPE zlmediakit_statistics_buffer_like_string gauge
zlmediakit_statistics_buffer_like_string 3
# HELP zlmediakit_statistics_buffer_list Statistics BufferList
# TYPE zlmediakit_statistics_buffer_list gauge
zlmediakit_statistics_buffer_list 0
# HELP zlmediakit_statistics_buffer_raw Statistics BufferRaw
# TYPE zlmediakit_statistics_buffer_raw gauge
zlmediakit_statistics_buffer_raw 8
# HELP zlmediakit_statistics_frame Statistics Frame
# TYPE zlmediakit_statistics_frame gauge
zlmediakit_statistics_frame 0
# HELP zlmediakit_statistics_frame_imp Statistics FrameImp
# TYPE zlmediakit_statistics_frame_imp gauge
zlmediakit_statistics_frame_imp 0
# HELP zlmediakit_statistics_media_source Statistics MediaSource
# TYPE zlmediakit_statistics_media_source gauge
zlmediakit_statistics_media_source 0
# HELP zlmediakit_statistics_multi_media_source_muxer Statistics MultiMediaSourceMuxer
# TYPE zlmediakit_statistics_multi_media_source_muxer gauge
zlmediakit_statistics_multi_media_source_muxer 0
# HELP zlmediakit_statistics_rtmp_packet Statistics RtmpPacket
# TYPE zlmediakit_statistics_rtmp_packet gauge
zlmediakit_statistics_rtmp_packet 0
# HELP zlmediakit_statistics_rtp_packet Statistics RtpPacket
# TYPE zlmediakit_statistics_rtp_packet gauge
zlmediakit_statistics_rtp_packet 0
# HELP zlmediakit_statistics_socket Statistics Socket
# TYPE zlmediakit_statistics_socket gauge
zlmediakit_statistics_socket 59
# HELP zlmediakit_statistics_tcp_client Statistics TcpClient
# TYPE zlmediakit_statistics_tcp_client gauge
zlmediakit_statistics_tcp_client 1
# HELP zlmediakit_statistics_tcp_server Statistics TcpServer
# TYPE zlmediakit_statistics_tcp_server gauge
zlmediakit_statistics_tcp_server 43
# HELP zlmediakit_statistics_tcp_session Statistics TcpSession
# TYPE zlmediakit_statistics_tcp_session gauge
zlmediakit_statistics_tcp_session 2
# HELP zlmediakit_statistics_udp_server Statistics UdpServer
# TYPE zlmediakit_statistics_udp_server gauge
zlmediakit_statistics_udp_server 16
# HELP zlmediakit_statistics_udp_session Statistics UdpSession
# TYPE zlmediakit_statistics_udp_session gauge
zlmediakit_statistics_udp_session 0
# HELP zlmediakit_up Was the last scrape of ZLMediaKit successful.
# TYPE zlmediakit_up gauge
zlmediakit_up 1
# HELP zlmediakit_version_info ZLMediaKit version info.
# TYPE zlmediakit_version_info gauge
zlmediakit_version_info{branchName="master",buildTime="2024-06-11T21:28:30",commitHash="c446f6b"} 1
# HELP zlmediakit_work_threads_delay_total Total of work threads delay
# TYPE zlmediakit_work_threads_delay_total gauge
zlmediakit_work_threads_delay_total 17
# HELP zlmediakit_work_threads_load_total Total of work threads load
# TYPE zlmediakit_work_threads_load_total gauge
zlmediakit_work_threads_load_total 0
# HELP zlmediakit_work_threads_total Total number of work threads
# TYPE zlmediakit_work_threads_total gauge
zlmediakit_work_threads_total 8
</details>

## TODO

- [ ] GA
- [ ] Add grafana dashboard example
- [ ] Add prometheus alert example
- [ ] Add git action CI/CD,and trigger docker build and push to docker hub
- [ ] Add more tests
- [ ] Add more metrics

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