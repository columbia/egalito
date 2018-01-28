#!/bin/sh
ulimit

N=3
file=${1:-index.html}

echo "=== nginx.sh ==="
counter=0
while [ $counter -lt $N ]; do
  ./nginx.sh $file && cat tmp/nginx-wrk.out
  counter=$((counter+1))
  while $(netstat | grep -q 'TIME_WAIT'); do
    sleep 10
  done
  echo $(netstat | grep -q 'TIME_WAIT')
done

echo "=== nginx-thread.sh ==="
counter=0
while [ $counter -lt $N ]; do
  ./nginx-thread.sh $file && cat tmp/nginx-thread-wrk.out
  counter=$((counter+1))
  while $(netstat | grep -q 'TIME_WAIT'); do
    sleep 10
  done
  echo $(netstat | grep -q 'TIME_WAIT')
done

echo "=== nginx-jitonce.sh ==="
counter=0
while [ $counter -lt $N ]; do
  ./nginx-jitonce.sh $file && cat tmp/nginx-jitonce-wrk.out
  counter=$((counter+1))
  while $(netstat | grep -q 'TIME_WAIT'); do
    sleep 10
  done
  echo $(netstat | grep -q 'TIME_WAIT')
done

echo "=== nginx-thread-jitonce.sh ==="
counter=0
while [ $counter -lt $N ]; do
  ./nginx-thread-jitonce.sh $file && cat tmp/nginx-thread-jitonce-wrk.out
  counter=$((counter+1))
  while $(netstat | grep -q 'TIME_WAIT'); do
    sleep 10
  done
  echo $(netstat | grep -q 'TIME_WAIT')
done

echo "=== nginx-jitshuffle.sh ==="
counter=0
while [ $counter -lt $N ]; do
  ./nginx-jitshuffle.sh $file && cat tmp/nginx-jitshuffle-wrk.out
  counter=$((counter+1))
  while $(netstat | grep -q 'TIME_WAIT'); do
    sleep 10
  done
  echo $(netstat | grep -q 'TIME_WAIT')
done

echo "=== nginx-thread-jitshuffle.sh ==="
counter=0
while [ $counter -lt $N ]; do
  ./nginx-thread-jitshuffle.sh $file && cat tmp/nginx-thread-jitshuffle-wrk.out
  counter=$((counter+1))
  while $(netstat | grep -q 'TIME_WAIT'); do
    sleep 10
  done
  echo $(netstat | grep -q 'TIME_WAIT')
done

