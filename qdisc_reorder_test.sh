#!/bin/sh

NCLIENTS=4

create_namespace () {
    local nsname=$1
    if [ -e /var/run/netns/$nsname ] ; then
        ip netns delete $nsname
    fi
    ip netns add $nsname
}

create_setns_veth () {
    local veth1=$1
    local ns1=$2
    local veth2=$3
    local ns2=$4
    ip link add dev $veth1 type veth peer name $veth2
    ip link set dev $veth1 netns $ns1
    ip link set dev $veth2 netns $ns2
}

setup_interface () {
    local ifname=$1
    local addr=$2
    local ns=$3

    ip netns exec $ns ethtool -K $ifname tso off
    ip netns exec $ns ethtool -K $ifname gso off
    ip netns exec $ns sysctl -q -w net.ipv4.conf.$ifname.rp_filter=0
    ip netns exec $ns ip addr add $addr dev $ifname
    ip netns exec $ns ip link set dev $ifname up
}

OUTPUT_FOLDER="test-output"
mkdir -p "$OUTPUT_FOLDER"

create_namespace "ns0"
create_namespace "ns1"
create_namespace "ns2"

create_setns_veth "veth01" "ns0" "veth10" "ns1"
create_setns_veth "veth12" "ns1" "veth21" "ns2"

setup_interface "veth01" "10.255.0.2/24" "ns0"
setup_interface "veth10" "10.255.0.1/24" "ns1"
setup_interface "veth12" "10.0.0.1/24" "ns1"
setup_interface "veth21" "10.0.0.2/24" "ns2"

ip netns exec ns0 ip route add default via 10.255.0.1 dev veth01 initcwnd 10
ip netns exec ns1 ip route add 10.0.0.2 via 10.0.0.1 dev veth12
ip netns exec ns2 ip route add default via 10.0.0.1 dev veth21 initcwnd 10

ip netns exec ns1 ip link set veth12 txqueuelen 1000
ip netns exec ns1 tc qdisc add dev veth12 root handle 1: htb default 2
ip netns exec ns1 tc class add dev veth12 parent 1: classid 1:1 htb rate 1000Mbit
ip netns exec ns1 tc class add dev veth12 parent 1:1 classid 1:2 htb rate 1000Mbit ceil 1000Mbit

ip netns exec ns0 tcpdump -n -i veth01 -w "$OUTPUT_FOLDER"/tcpdump_out_ns0.dump -Z root 'tcp and (src port 6000 or dst port 6000)' 2> "$OUTPUT_FOLDER"/tcpdump_log_ns0 &
client_dump=$!
ip netns exec ns2 tcpdump -n -i veth21 -w "$OUTPUT_FOLDER"/tcpdump_out_ns2.dump -Z root 'tcp and (src port 6000 or dst port 6000)' 2> "$OUTPUT_FOLDER"/tcpdump_log_ns2 &
server_dump=$!

offset=3
RUNTIME=60s
for i in $(seq 0 $((NCLIENTS-1))); do
    classid="1:$((offset + i))"
    port=$((6000 + i))
    ip netns exec ns1 tc class add dev veth12 parent 1:1 classid "$classid" htb rate 1000Mbit ceil 1000Mbit
    ip netns exec ns1 tc filter add dev veth12 parent 1:0 protocol ip u32 match ip sport "$port" 0xffff flowid "$classid"
    ip netns exec ns0 iperf3 --server --port "$port" --one-off --daemon
    ip netns exec ns2 iperf3 --client 10.255.0.2 --port "$port" --time $RUNTIME --reverse --bitrate 5Mbit --parallel 4 --interval $RUNTIME > "$OUTPUT_FOLDER"/iperf3_sender"$i"_out &
done

sleep "$RUNTIME"

kill $client_dump
kill $server_dump

wait
sync

ip netns exec ns1 tc -s qd show dev veth12 > "$OUTPUT_FOLDER"/qdisc_stats_output
ip netns exec ns1 tc -s -g class show dev veth12 > "$OUTPUT_FOLDER"/class_stats_output