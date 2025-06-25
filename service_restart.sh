PORTS="28358 8398"
for port in $PORTS; do
    pid=$(lsof -ti :$port)
    
    if [ -z "$pid" ]; then
        echo "端口 $port 当前未被占用"
    else
        echo "正在终止占用 $port 的进程 $pid ..."
        kill -9 $pid
    fi
done

cd /root/threat-spider/threat-demo
mvn spring-boot:run &
cd python_spider
python3 manage.py runserver 127.0.0.1:8398 --noreload &
