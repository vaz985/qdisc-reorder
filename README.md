# qdisc-reorder

We found that HTB causes packet reordering when packets are forwarded over veth devices connecting different network namespaces. We create three namespaces connected by two veths:

```{text}
ns0          ns1          ns2
veth01 <---> veth10
             veth12 <---> veth21
```

We set up 4 TCP connections between 4 different server-client pairs. Servers run in ns0, clients run in ns2, and the bulk of the bytes traverse veth01 → veth10 → veth12 → veth2. We configure HTB to shape traffic leaving veth12. We configure the parent class with 1000mb rate and configure one leaf class per server-client pair with 1000mbit rate (dedicated) with 1000-packet buffers:

```{bash}
ip netns exec ns1 ip link set veth12 txqueuelen 1000
ip netns exec ns1 tc qdisc add dev veth12 root handle 1: htb default 2
ip netns exec ns1 tc class add dev veth12 parent 1: classid 1:1 htb rate 1000Mbit
ip netns exec ns1 tc class add dev veth12 parent 1:1 classid 1:2 htb rate 1000Mbit ceil 1000Mbit
for i in 0 1 2 3 ; do
    classid=1:$((4 + i))
    port=$((6000 + i))
    ip netns exec ns1 tc class add dev veth12 parent 1:1 \
        classid "$classid" htb rate 1000Mbit ceil 1000Mbit
    ip netns exec ns1 tc filter add dev veth12 parent 1:0 \
        protocol ip u32 match ip sport "$port" 0xffff flowid "$classid"
done
```

To showcase the reordering, we limit iperf’s transfer rate to 20mbit to avoid packet drops at veth12. However, looking at iperf’s output we can see that a significant number of packets were retransmitted, and looking at tcpdump we can see that packets are reordered. Below is one example from one connection showing packets arriving out-of-order at veth21 (captures from veth01 are sorted by time and sequence number, captures from veth21 are sorted by time but sequence numbers are out of order).

```{text}
veth01 tcpdump                 veth21 tcpdump
Time=2.412032 Seq=3014657      Time=2.412144 Seq=3014657
Time=2.412031 Seq=3016105      Time=2.412158 Seq=3017553
Time=2.412030 Seq=3017553      Time=2.412162 Seq=3016105
Time=2.412029 Seq=3019001      Time=2.412176 Seq=3024793
Time=2.412028 Seq=3020449      Time=2.412180 Seq=3020449
Time=2.412027 Seq=3021897      Time=2.412184 Seq=3027689
Time=2.412026 Seq=3023345      Time=2.412203 Seq=3023345
```

The qdist_reorder_test.sh script in the Git repo below can be used to
run the tests, and dumpcheck.py can be used to get statistics on packet
reordering from the two packet capture dumps. The dumpcheck.py script
does not need root permissions and can be run with:

```{bash}
./dumpcheck.py --server-dump test-output/tcpdump_out_ns0.dump.gz \
        --client-dump test-output/tcpdump_out_ns2.dump.gz \
        --output summary.txt
```

We were able to reproduce this problem on vanilla kernel version 4.19.208 and 5.15.
