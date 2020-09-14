# MySQL Router Exporter

[![Build Status](https://github.com/daixijun/mysqlrouter_exporter/workflows/goreleaser/badge.svg)](https://github.com/daixijun/mysqlrouter_exporter/actions?query=workflow%3goreleaser)

MySQL Router Exporter， 基于 rluisr 大神 [mysqlrouter_exporter](https://github.com/rluisr/mysqlrouter_exporter) 的版本重写

重写的原因有两个

1. rluisr 大神的版本是每 2 秒收集一次指标放在内存中，运行时间长了后内存占用会很大，且指标内容过后多会造抓取时间过长
2. 学习下 exporter 的编写

## 支持的 MySQL Router 版本

理论上 8.0.17 以上版本都支持

具体参考 mysqlrouter-go [supported-version](https://github.com/rluisr/mysqlrouter-go#supported-version)

## 编译

> 基于 go 1.15 开发

使用 [goreleaser](https://goreleaser.com/) 工具进行编译

```sh
## 只编译
$ goreleaser build --rm-dist
## 编译并上传附件到github
$ goreleaser release --rm-dist
```

## 运行

> 参数 `--mysqlrouter.scrape-uri`、`--mysqlrouter.username`、`--mysqlrouter.password` 可以分别使用环境变量 `MYSQLROUTER_URI`、`MYSQLROUTER_USERNAME`和`MYSQLROUTER_PASSWORD` 进行覆盖

```sh
$ ./mysqlrouter_exporter --help
usage: mysqlrouter_exporter [<flags>]

Flags:
  -h, --help                     Show context-sensitive help (also try --help-long and --help-man).
      --web.listen-address=":49152"
                                 Address to listen on for web interface and telemetry.
      --web.telemetry-path="/metrics"
                                 Path under which to expose metrics.
      --mysqlrouter.scrape-uri="http://localhost:8081"
                                 URI on which to scrape mysqlrouter.
      --mysqlrouter.username=""  Flag that username for the scrape URI
      --mysqlrouter.password=""  Flag that password for the scrape URI
      --mysqlrouter.pid-file=""  Path to mysqlrouter pid file.

                                   If provided, the standard process metrics get exported for the mysqlrouter
                                   process, prefixed with 'mysqlrouter_process_...'. The mysqlrouter_process exporter
                                   needs to have read access to files owned by the mysqlrouter process. Depends on
                                   the availability of /proc.
                                   https://prometheus.io/docs/instrumenting/writing_clientlibs/#process-metrics.
      --log.level=info           Only log messages with the given severity or above. One of: [debug, info, warn, error]
      --log.format=logfmt        Output format of log messages. One of: [logfmt, json]
      --version                  Show application version.
```

## 安装步骤

1. 需要开启 mysql router 的 rest api 功能

   参考 [A Simple MySQL Router REST API Guide](https://dev.mysql.com/doc/mysql-router/8.0/en/mysql-router-rest-api-setup.html)

2. 下载编译好的二进制文件到 /usr/local/bin/

   https://github.com/daixijun/mysqlrouter_exporter/releases

3. 添加用于启动进程的用户(可选)

   ```sh
   $ useradd --comment "mysqlrouter exporter" --no-create-home --system --shell /usr/sbin/nologin mysqlrouter_exporter
   ```

4. 创建 systemd 配置.

   ```sh
   $ cat > /etc/systemd/system/mysqlrouter_exporter.service <<EOF
   [Unit]
   Description=mysqlrouter-exporter
   Documentation=https://github.com/daixijun/mysqlrouter_exporter
   After=network-online.target

   [Service]
   Type=simple
   Environment="MYSQLROUTER_URI=https://mysqlrouter-test.xzy.pw"
   Environment="MYSQLROUTER_USERNAME=luis"
   Environment="MYSQLROUTER_PASSWORD=luis"
   ExecStart=/usr/local/bin/mysqlrouter_exporter
   User=mysqlrouter_exporter
   Group=mysqlrouter_exporter
   Restart=always
   Type=simple

   [Install]
   WantedBy=multi-user.target
   EOF
   ```

5. 设置开机自启动

   ```sh
   systemctl enable --now mysqlrouter_exporter.service
   ```

## Prometheus configuration

```yaml
scrape_configs:
  - job_name: "mysqlrouter"
    static_configs:
      - targets:
          - 127.0.0.1:49152
```

## Grafana Dashboard

![Grafana Dashboard](https://grafana.com/api/dashboards/10741/images/6783/image "Grafana Dashboard")

available [here](https://grafana.com/grafana/dashboards/10741).

## 感谢

- [@rluisr](https://github.com/rluisr)
