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
curl 'http://localhost:9200/_search?pretty&q=Felipe'
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
    path => "/var/log/apache2/access.log"
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

[Sintaxis Grok](https://github.com/elasticsearch/logstash/blob/v1.4.0/patterns/grok-patterns)

* Multiline
```
input {
  file {
      path => "/home/philippe/Desktop/logstash-1.4.2/error.log"
      start_position => "beginning"
      codec => multiline {      
	      pattern => "^\s"
      	      what => "previous"
    	}
   }
}

output {   
  stdout { codec => rubydebug }
}
```
Archivo de error.log
```
java.lang.Exception: Stack trace at java.lang.Thread.dumpStack(Thread.java:1249) at test.StringReplace.third(StringReplace.java:38) at test.StringReplace.second(StringReplace.java:31) at test.StringReplace.first(StringReplace.java:27) at test.StringReplace.main(StringReplace.java:23) Printing stack trace using printStackTrace() method of Throwable java.lang.Throwable at test.StringReplace.third(StringReplace.java:42) at test.StringReplace.second(StringReplace.java:31) at test.StringReplace.first(StringReplace.java:27) at test.StringReplace.main(StringReplace.java:23) displaying Stack trace from StackTraceElement in Java

Read more: http://javarevisited.blogspot.com/2013/04/how-to-get-current-stack-trace-in-java-thread.html#ixzz3Rwftda8u
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
* Instalar Bitcoin
  * wget `https://bitcoin.org/bin/0.9.3/bitcoin-0.9.3-linux.tar.gz`
  * `tar xvzf bitcoin-0.9.3-linux.tar.gz`
  * `cd bitcoin-0.9.3-linux/bin/32`
  * `./bitcoind`
* Link util: http://grokdebug.herokuapp.com/


* Archivo de configuracion `blockchain.conf`
```
input {
  file {
    path => "/home/philippe/.bitcoin/debug.log"
    start_position => beginning
  }
}

filter {
  grok {
    match => { "message" => "%{DATESTAMP}%{SPACE}%{WORD}:%{SPACE}new%{SPACE}best=%{WORD:difficulty}%{SPACE}height=%{WORD}%{SPACE}log2_work=%{NUMBER:log2_work}%{SPACE}tx=%{NUMBER:tx}%{SPACE}date=%{TIMESTAMP_ISO8601:bitcoin_date_stamp}%{SPACE}progress=%{NUMBER:progress}" }
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

### Interopeabilidad Logstash y Graylog a traves de GELF
* Ver http://logstash.net/docs/1.4.2/outputs/gelf
* Permite enviar datos estructurados de Logstash a Graylog
* OJO: Input GELP solo funciona con UDP
```
input {
  file {
    path => "/home/philippe/.bitcoin/debug.log"
    start_position => beginning
  }
}


filter {
  grok {
    match => { "message" => "%{DATESTAMP}%{SPACE}%{WORD}:%{SPACE}new%{SPACE}best=%{WORD:_difficulty}%{SPACE}height=%{WORD}%{SPACE}log2_work=%{NUMBER:log2_work}%{SPACE}tx=%{NUMBER:tx}%{SPACE}date=%{TIMESTAMP_ISO8601:bitcoin_date_stamp}%{SPACE}progress=%{NUMBER:progress}" }
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

  gelf {
    host => localhost 
    port => 12203
  }

}
```

* Extractores
 * Convertir un campo a tipo NUM para hacer estadisticas



#### Streams
 * Exp regular para año 2012: 2012(.*)


#### Integración con Slack
 * Ver https://www.graylog.org/resource/plugin/545cc0ace4b0d324cb87ad6d/
 * Crear un token para la API: 
 * Bajar [graylog2-alarmcallback-slack-0.90.0.jar](graylog2-alarmcallback-slack-0.90.0.jar)
 * Copiar el archivo `.jar` en el directorio de los plugins de Graylog2 que esta definido en `graylog2.conf`
  * `sudo cp graylog-alarmcallback-slack-1.0.0-SNAPSHOT.jar /usr/share/graylog2-server/plugin/`
 * Reiniciar servidor graylog
 * Crear Stream > 
 * Manage Alerts > Slack alarm callback. Guardar
 * En la configuración del canal usar #<nombre canal>
 * No es necesario poner nombre de usuario. Basta con el token de la API

## Dashboard
 * Hacer una query
 * Luego apretar boton add to dashboard (icono azul: aguja)






