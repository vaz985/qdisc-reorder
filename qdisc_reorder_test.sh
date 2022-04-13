#!/bin/bash
set -eu

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

create_setns_veth "veth0" "ns0" "veth1" "ns1"

setup_interface "veth0" "10.255.0.2/32" "ns0"
setup_interface "veth1" "10.0.0.2/32" "ns1"

ip netns exec ns0 ip route add 10.0.0.2/32 via 10.255.0.2 dev veth0 initcwnd 10
ip netns exec ns1 ip route add 10.255.0.2/32 via 10.0.0.2 dev veth1 initcwnd 10

ip netns exec ns0 lighttpd -f lighttpd.conf

ip netns exec ns0 \
        tcpdump -n -i veth0 -w "$OUTPUT_FOLDER"/tcpdump_out_ns0.dump -Z root \
        'tcp' 2> "$OUTPUT_FOLDER"/tcpdump_log_ns0 &
server_tcpdump=$!
ip netns exec ns1 \
        tcpdump -n -i veth1 -w "$OUTPUT_FOLDER"/tcpdump_out_ns1.dump -Z root \
        'tcp' 2> "$OUTPUT_FOLDER"/tcpdump_log_ns1 &
client_tcpdump=$!

# ip netns exec ns0 python3 -m http.server > /dev/null 2> /dev/null &
# server_pid=$!

# Wait programs properly initialize
sleep 2

mkdir -p www
head -c "2048k" < /dev/urandom > "www/2048k.bin"

for _ in $(seq 100); do
    ip netns exec ns1 wget 10.255.0.2/2048k.bin --output-document=/dev/null \
        --no-http-keep-alive --no-cache --no-cookies
    sleep 0.1
done

sleep 2

kill $server_tcpdump
kill $client_tcpdump
# kill $server_pid
pkill --pidfile "lighttpd.pid"

wait
sync

gzip -f "$OUTPUT_FOLDER/tcpdump_out_ns0.dump"
gzip -f "$OUTPUT_FOLDER/tcpdump_out_ns1.dump"

rm lighttpd.pid
rm -r www

ip netns delete ns0
ip netns delete ns1