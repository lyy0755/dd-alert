ELK接收Paloalto日志并用钉钉告警.

运行命令：
./elasticsearch-5.5.2/bin/elasticsearch &

./kibana-5.5.2-linux-x86_64/bin/kibana &

./logstash-5.5.2/bin/logstash -f /xxxx/logstash-5.5.2/syslog.conf &

python -m ./elastalert/elastalert.elastalert --verbose &
