#!/bin/bash
for i in {0..39}; do {
  echo "Process \"$i\" started";
  $cmd & pid=$!
  PID_LIST+=" $pid";
  (echo y; echo "123456")  | concordium-client contract update 5068 --entrypoint $1 --sender voter${i+1} --parameter-binary parameters/$1_msgs/$1_msg$i.bin --energy 200000 --amount 1;
} done


trap "kill $PID_LIST" SIGINT

echo "Parallel processes have started";

wait $PID_LIST

echo
echo "All processes have completed";