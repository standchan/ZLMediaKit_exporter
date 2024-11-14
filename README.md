# zlm_exporter

![zlm_exporter](https://socialify.git.ci/standchan/zlm_exporter/image?language=1&owner=1&name=1&stargazers=1&theme=Light)

Prometheus exporter for [ZLMediaKit](https://github.com/ZLMediaKit/ZLMediaKit) metrics, written in Go.

[![](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/standchan/zlm_exporter/blob/master/LICENSE)
[![](https://img.shields.io/badge/language-golang-red.svg)](https://en.cppreference.com/)
[![](https://img.shields.io/badge/PRs-welcome-yellow.svg)](https://github.com/standchan/zlm_exporter/pulls)

## Installation

### Docker
```shell

```
### Binary


### Source
```shell
go get -u github.com/standchan/zlm_exporter
```

## Command line flags


|  Name     | Description                               | default  |
|-----------------|-------------------------------------------|----------|
| `kafka_brokers` | Number of Brokers in the Kafka Cluster    | |
| `kafka_topics`  | Number of Topics in the Kafka Cluster     | |
| `kafka_partitions`  | Number of Partitions in the Kafka Cluster | |


## Metrics

| Metric Name     | Description                            |
|-----------------|----------------------------------------|
| `kafka_brokers` | Number of Brokers in the Kafka Cluster |
| `kafka_topics`  | Number of Topics in the Kafka Cluster  |
| `kafka_partitions`  | Number of Partitions in the Kafka Cluster|


## Contributing and reporting issues

JUST DO IT! 

We are happy to receive your feedback and contributions.


## Thanks
[ZLMediaKit](https://github.com/ZLMediaKit/ZLMediaKit)
[jetbrains](https://www.jetbrains.com/)

jetbrains provides great IDEs for development