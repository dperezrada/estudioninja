# Tutorial Logtash + Graylog


## Getting Started

### Logtash

* Instalar Ubuntu 14.04 32 bits
* Para VirtualBox
```
sudo apt-get install virtualbox-guest-dkms \
virtualbox-guest-utils virtualbox-guest-x11
sudo apt-get install curl
```
* Instalar Java: `sudo apt-get install openjdk-7-jdk`
* Bajar Logtash: `curl -O https://download.elasticsearch.org/logstash/logstash/logstash-1.4.2.tar.gz`
* Descomprimir: `tar zxvf logstash-1.4.2.tar.gz` 
* `cd logstash-1.4.2`
* Hola mundo `bin/logstash -e 'input { stdin { } } output { stdout {} }'`
* Resultado
```
hello world
2013-11-21T01:22:14.405+0000 0.0.0.0 hello world
```

* Usando un codec
`bin/logstash -e 'input { stdin { } } output { stdout { codec => rubydebug } }'`

```
goodnight moon
{
  "message" => "goodnight moon",
  "@timestamp" => "2013-11-20T23:48:05.335Z",
  "@version" => "1",
  "host" => "my-laptop"
}
```

* Instalar Elastic Search

```shell
wget -qO - https://packages.elasticsearch.org/GPG-KEY-elasticsearch | sudo apt-key add -
sudo add-apt-repository "deb http://packages.elasticsearch.org/elasticsearch/1.4/debian stable main"
sudo apt-get update && sudo apt-get install elasticsearch
sudo update-rc.d elasticsearch defaults 95 10
sudo service elasticsearch start
```

* Enviar log a Elastic Search
```
bin/logstash -e 'input { stdin { } } output { elasticsearch { host => localhost } }'
you know, for logs
curl 'http://localhost:9200/_search?pretty'
```

* Multiples salidas
`bin/logstash -e 'input { stdin { } } output { elasticsearch { host => localhost } stdout { } }'`

* Usando un archivo de configuracion
 * En archivo logstash-simple.conf
```
input { stdin { } }
output {
  elasticsearch { host => localhost }
  stdout { codec => rubydebug }
}
```

* Usando grok (filtro)
```
input { stdin { } }

filter {
  grok {
    match => { "message" => "%{COMBINEDAPACHELOG}" }
  }
  date {
    match => [ "timestamp" , "dd/MMM/yyyy:HH:mm:ss Z" ]
  }
}

output {
  elasticsearch { host => localhost }
  stdout { codec => rubydebug }
}
```

* Ejemplo "util"
```
input {
  file {
    path => "/tmp/access_log"
    start_position => beginning
  }
}

filter {
  if [path] =~ "access" {
    mutate { replace => { "type" => "apache_access" } }
    grok {
      match => { "message" => "%{COMBINEDAPACHELOG}" }
    }
  }
  date {
    match => [ "timestamp" , "dd/MMM/yyyy:HH:mm:ss Z" ]
  }
}

output {
  elasticsearch {
    host => localhost
  }
  stdout { codec => rubydebug }
}
```

* Syslog
```
input {
  tcp {
    port => 5000
    type => syslog
  }
  udp {
    port => 5000
    type => syslog
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    syslog_pri { }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}

output {
  elasticsearch { host => localhost }
  stdout { codec => rubydebug }
}
```
 * `bin/logstash -f logstash-syslog.conf`
 * `telnet localhost 5000`
 
```
Dec 23 12:11:43 louis postfix/smtpd[31499]: connect from unknown[95.75.93.154]
Dec 23 14:42:56 louis named[16000]: client 199.48.164.7#64817: query (cache) 'amsterdamboothuren.com/MX/IN' denied
Dec 23 14:30:01 louis CRON[619]: (www-data) CMD (php /usr/share/cacti/site/poller.php >/dev/null 2>/var/log/cacti/poller-error.log)
Dec 22 18:28:06 louis rsyslogd: [origin software="rsyslogd" swVersion="4.2.0" x-pid="2253" x-info="http://www.rsyslog.com"] rsyslogd was HUPed, type 'lightweight'.
```

### Graylog

* Seguimos https://www.graylog.org/documentation/setup/server/
* Dependencias
 * Elastic Search v >=  1.3.4
   * Para levantarlo: `sudo service elasticsearch start`
 * Mongodb
  * `sudo apt-get install mongodb`
* `wget https://packages.graylog2.org/releases/graylog2-server/graylog2-server-0.92.4.tgz`
* `tar xvzf graylog2-server-0.92.4.tgz`
* `cd graylog2-server-0.92.4`
* `sudo cp graylog2.conf.example /etc/graylog2.conf`
* `sudo apt-get install pwgen`
* `pwgen -N 1 -s 96`
* `sudo nano /etc/graylog2.conf`
* `echo -n yourpassword | shasum -a 256`
* Cambiar en el archivo `/etc/graylog2.conf`
 * `password_secret = Cqxdr0ZFSuBFZ5uXVpu2lp9noUmUkZOVE7pc9Dljybarrt60zc6AByVEF2uL4`
 * `root_username = admin`
 * `root_password_sha2 = 8c6976e5b5410415bde908bd4dee15...` (con el hash de yourpassword obtenido en el paso anterior)
 * `elasticsearch_cluster_name = elasticsearch`
 * `elasticsearch_discovery_zen_ping_multicast_enabled = false`
 * `elasticsearch_discovery_zen_ping_unicast_hosts = localhost:9300` 
 * `elasticsearch_config_file = /etc/elasticsearch/elasticsearch.yml`
* Lanzar el servidor
 * `sudo java -jar graylog2-server.jar --debug`
* Instalar la interfaz web
 * `https://www.graylog.org/documentation/setup/webinterface/`
 * `wget https://packages.graylog2.org/releases/graylog2-web-interface/graylog2-web-interface-0.92.4.tgz`
 * `tar xvzf graylog2-web-interface-0.92.4.tgz`
 * `cd graylog2-web-interface-0.92.4`
 * Abrir `conf/graylog2-web-interface.conf` y cambiar los campos siguientes
   * `graylog2-server.uris="http://127.0.0.1:12900/"`
  * `application.secret="..."` usando pwgen
 * Lanzar
  * `./bin/graylog2-web-interface`
* Crear entradas
 * System -> Nodes. Select your graylog2-server node there and click on Manage inputs.
 * Elegir Raw UDP
 * Eligir puerto distinto de 5555
 * `echo "Hello Graylog2, let's be friends." | nc -w 1 -u 127.0.0.1 9099`


## Monitor blockchain
Usa logstash y graylog 

* Archivo de configuracion `blockchain.conf`
```
input {
  file {
    path => "/home/philippe/.bitcoin/debug.log"
    start_position => beginning
  }
}


output {
  stdout { codec => rubydebug }
  tcp {
    codec => json_lines
    host => localhost     
    mode => client
    port => 11368
  }
}
```

## Integración con Slack
 * Crear un token para la API: xoxp-2750676142-2754457234-3678303963-76eaa1
 * Bajar [graylog-alarmcallback-slack-1.0.0-SNAPSHOT.jar](estudioninja/experimentos/log-management/graylog-alarmcallback-slack-1.0.0-SNAPSHOT.jar)





