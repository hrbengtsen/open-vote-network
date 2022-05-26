#!/bin/bash
for i in {0..39}; do {
  echo "Process \"$i\" started";
  $cmd & pid=$!
  PID_LIST+=" $pid";
  (echo y; echo "123456")  | concordium-client contract update 5067 --entrypoint register --sender voter${i+1} --parameter-binary parameters/register_msgs/register_msg$j.bin --energy 100000 --amount 1;
} done


trap "kill $PID_LIST" SIGINT

echo "Parallel processes have started";

wait $PID_LIST

echo
echo "All processes have completed";