#!/bin/bash

if [ $# == 0 ]; then
  filename=index.html
else
  filename=$1
fi

command -v wrk > /dev/null 2>&1 || { echo >&2 "needs wrk -- skipping"; exit 0; }

mkdir -p tmp
ln -sf ../../src/libegalito.so

pidfile=../binary/target/nginx/nginx/logs/nginx.pid
rm -f $pidfile

EGALITO_DEBLOAT=1 EGALITO_USE_GS=1 \
../../src/loader ../binary/target/nginx/nginx/sbin/nginx -c ../conf-aio/nginx.conf >tmp/nginx-thread-jitonce.out 2>& 1 &

count=50
while [ ! -f $pidfile ]; do
  sleep 1;
  count=$((count-1))
  if [[ "$count" -eq 0 ]]; then
    echo "test failed";
    exit 1;
  fi
done
#cat $pidfile

wrk -c10 -d30s -t4 http://localhost:8000/$filename > tmp/nginx-thread-jitonce-wrk.out

kill -QUIT $( cat $pidfile )
kill -KILL $( cat $pidfile )
killall loader
rm -f $pidfile

#kill -QUIT $( cat $pidfile )

#count=50
#while [ -f $pidfile ]; do
  #sleep 1;
  #if [[ "$count" -eq 0 ]]; then
    #echo "test failed";
    #exit 1;
  #fi
#done

rm libegalito.so
echo "test passed"
