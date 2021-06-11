#!/bin/sh
echo "Force the kernel to re-create the dummy mq scheduler on the default interface."
sysctl -w net.core.default_qdisc=fq_codel
tc qdisc del dev "$(route | grep '^default' | grep -o '[^ ]*$')" root 2>/dev/null || true
tc qdisc add dev "$(route | grep '^default' | grep -o '[^ ]*$')" root handle 0: mq || true
echo "Waiting for eth0 interface to come up."
while ! ip link | grep "eth0:" > /dev/null; do sleep 1; done
tc qdisc del dev eth0 root 2>/dev/null || true
tc qdisc add dev eth0 root handle 1: prio bands 2 priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
tc qdisc add dev eth0 parent 1:2 handle 12: fq_codel
echo "Injecting a small delay using netem."
tc qdisc add dev eth0 parent 1:1 handle 11: netem delay 4ms 1ms distribution pareto
tc filter add dev eth0 protocol all parent 1: prio 1 handle 0x100/0x100 fw flowid 1:1
echo "Marking DNS traffic using iptables."
iptables -A POSTROUTING -t mangle -p udp --dport 53 -m string -m u32 --u32 "28 & 0xF8 = 0" --hex-string "|00001C0001|" --algo bm --from 40 -j MARK --set-mark 0x100/0x100 -w
echo "Setup completed."
