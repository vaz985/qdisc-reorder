# qdisc-reorder

We found packet reordering when TCP packets are transferred over veth devices
connecting different network namespaces. We create two namespaces connected by a
pair of veths and disabled tso/gso to remove offloading.

```
Dependencies:
apt install ethtool lighttpd tcpdump
```

To reproduce our environment, set up a lighttpd web server at ns0 with fixed
size files, fetch files at ns1 using wget and capture packets on both veth’s
using tcpdump. Running several transfers of 2048KiB we were able to detect
transfers with reordered packets, and in some cases those reordered packets
triggered retransmissions. The example below shows a sample case of the state of
the packets before and after going through the veth pair (we made sure those are
the same packets, not retransmitted).

```
veth0 tcpdump                  veth1 tcpdump
Time=23.284372 Seq=900169      Time=23.284487 Seq=909481
Time=23.284374 Seq=901617      Time=23.284488 Seq=900169
Time=23.284377 Seq=903065      Time=23.284490 Seq=910929
Time=23.284379 Seq=905961      Time=23.284491 Seq=901617
Time=23.284381 Seq=907409      Time=23.284492 Seq=912377
Time=23.284383 Seq=908857      Time=23.284493 Seq=903065
Time=23.284384 Seq=909481      Time=23.284495 Seq=913825
Time=23.284428 Seq=910929      Time=23.284495 Seq=905961
Time=23.284430 Seq=912377      Time=23.284496 Seq=916721
Time=23.284431 Seq=913825      Time=23.284498 Seq=905961
```

We tried different qdisc to understand the scope of the problem and were able to
reproduce on tc-fq, tc-pfifo_fast and netem (we didn't test others, but expect
the problem to persist). Using netem we were able to reduce and even suppress
reordering by reducing the rate, because of that we speculate the burst of
packets to be what causes the problem. We also tested this under different
machines and using kernel 4.20, 5.15 and 5.16. Is this behavior expected?

The qdist_reorder_test.sh script in the Git repo below can be used to run the
tests, and dumpcheck.py can be used to get statistics on packet reordering from
the two packet capture dumps. The dumpcheck.py script does not need root
permissions and can be run with:

```{bash}
./dumpcheck.py --server-dump test-output/tcpdump_out_ns0.dump.gz \
        --client-dump test-output/tcpdump_out_ns2.dump.gz \
        --output summary.txt
```