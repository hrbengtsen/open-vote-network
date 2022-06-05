#!/bin/bash
for i in {1..5}; do {
  echo "--------------- VOTER \"$i\" ---------------" >> $1_output.txt;
  $cmd & pid=$!
  PID_LIST+=" $pid";
  (echo y; echo "123456")  | concordium-client contract update $2 --entrypoint $1 --sender voter$i --parameter-binary parameters/$1_msgs/$1_msg$i.bin --energy 250000 $3 >> $1_output.txt
  
} done


trap "kill $PID_LIST" SIGINT

echo "Parallel processes have started";

wait $PID_LIST

echo
echo "All processes have completed";