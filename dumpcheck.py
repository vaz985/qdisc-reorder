#!/usr/bin/env python3

# This program parses tcpdump logs collected during emulations and
# computes the first lost segment, the number of retransmissions
# (segments), and the number of spurious retransmissions (segments), and
# the number of segments that arrive late (after another segment with a
# higher seqnum). When computing late arrivals, we only consider the
# first arrival of each segment (this limits the impact of multiple
# retransmissions, but the first retransmission of a lost packet will
# still be counted as a reordering event).
#
# This program requires two dumps: one collected at the server (before
# shaping qdiscs are traversed) and another collected at the client
# (after qdiscs are traversed). It only considers losses on the data
# sent from servers to clients. The program assumes all segments carry a
# whole MSS (so that retrasmitted segments carry the same sequence
# numbers as in the original segments).

from __future__ import annotations

import argparse
import collections
import dataclasses
import enum
import ipaddress
import logging
import pathlib
import re
import resource
import subprocess
import sys
import typing


class Flags(enum.Enum):
    ECE = "E"
    CWR = "C"
    URG = "U"
    ACK = "."
    PSH = "P"
    RST = "R"
    SYN = "S"
    FIN = "F"


class Errors(enum.Enum):
    MULTIPLE_SYN = "multiple-syn-packets-observed"
    MISSING_FIN = "missing-fin-packet"
    DROPPED_PACKETS = "dropped-packets"
    WRAP_AROUND = "seqnum-wrap-around"


@dataclasses.dataclass(eq=True, frozen=True, order=True)
class FlowSpec:
    src: ipaddress.IPv4Address
    dst: ipaddress.IPv4Address
    sport: int
    dport: int

    def __str__(self):
        return f"{self.src}:{self.sport} {self.dst}:{self.dport}"


@dataclasses.dataclass(eq=True, frozen=True, order=True)
class Segment:
    seq: int
    tsval: int
    flags: typing.Set[Flags]

    def number(self, mss: int) -> int:
        return 0 if Flags.SYN in self.flags else 1 + (self.seq - 1) // mss

    def __str__(self):
        flags = "".join(f.value for f in self.flags)
        return f"{self.tsval} {self.seq} {flags}"


@dataclasses.dataclass
class ConnectionSummary:
    first_lost: typing.Optional[Segment] = None
    flags: typing.Set[Flags] = dataclasses.field(default_factory=set)
    retransmissions: int = 0
    lost: int = 0
    late: int = 0
    segments_out: int = 0
    errors: typing.Set[Errors] = dataclasses.field(default_factory=set)

    @staticmethod
    def header_line() -> str:
        return "server client firstLoss flags retrans lost reorder packets errors\n"

    def to_string(self, mss: int) -> str:
        return " ".join(
            f"{d}" for d in [
                -1 if self.first_lost is None else self.first_lost.number(mss),
                "".join(f.value for f in self.flags),
                self.retransmissions,
                self.lost,
                self.late,
                self.segments_out,
                "ok" if not self.errors else ",".join(e.value for e in self.errors),
            ]
        )


class ConnectionLog:
    def __init__(self, flow: FlowSpec):
        self.flow = flow
        self.segments: list[Segment] = []

    def add(self, segment: Segment) -> None:
        self.segments.append(segment)

    @staticmethod
    def compare_server_client(server: ConnectionLog, client: ConnectionLog, opts) -> ConnectionSummary:
        def count_late_arrivals(clog: ConnectionLog) -> int:
            seen_seqs = set()
            late_arrivals = 0
            hiseq = -1
            for s in clog.segments:
                if s.seq >= hiseq:
                    hiseq = s.seq
                elif s.seq not in seen_seqs:
                    seen_seqs.add(s.seq)
                    late_arrivals += 1
            return late_arrivals

        csum = ConnectionSummary()
        server.segments.sort()
        if server.segments[-1].seq >= (2**32 - 4*opts.mss):
            # seqnum wrap-around. we disable TSO/GSO, but allow for 4
            # MSSs around the edges to account for coalesced segments.
            # we ignore connections with seqnum wrap-around.
            csum.errors.add(Errors.WRAP_AROUND)
            return csum
        csum.late = count_late_arrivals(client)
        # cannot sort client.segments before count_late_arrivals
        client.segments.sort()
        si = 0
        first_syn_seq = None
        sseqs_seen = set()
        for cseg in client.segments:
            if si == len(server.segments):
                csum.errors.add(Errors.DROPPED_PACKETS)
                break
            while si < len(server.segments):
                sseg = server.segments[si]
                si += 1
                if si > 0 and sseg.seq in sseqs_seen:
                    csum.retransmissions += 1
                csum.flags.update(sseg.flags)
                sseqs_seen.add(sseg.seq)
                if Flags.SYN in sseg.flags:
                    if first_syn_seq is None:
                        first_syn_seq = sseg.seq
                    if first_syn_seq != sseg.seq:
                        csum.errors.add(Errors.MULTIPLE_SYN)
                if cseg == sseg:
                    break
                csum.lost += 1
                if csum.first_lost is None:
                    csum.first_lost = sseg
        if Flags.FIN not in csum.flags:
            csum.errors.add(Errors.MISSING_FIN)
        csum.segments_out = len(server.segments)
        return csum


class ConnectionReader:
    def __init__(self, dump: pathlib.Path, server_network: ipaddress.IPv4Network):
        # tcpdump does not read gzip:
        # https://github.com/the-tcpdump-group/tcpdump/issues/254
        cmds = [
            f"zcat {dump}" if str(dump).endswith(".gz") else f"cat {dump}",
            f"tcpdump --absolute-tcp-sequence-numbers -n -r - tcp and src net {server_network}",
            'sort --stable --field-separator=" " -k3,5',
        ]
        self.dump = dump
        self.proc = subprocess.Popen(
            "|".join(cmds),
            bufsize=1,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            text=True,
        )
        self._readline()

    def close(self):
        for line in self.proc.stdout:
            pass
        logging.info("printing tcpdump stderr [%s]", self.dump)
        for line in self.proc.stderr:
            logging.info(line)
        self.proc.wait()

    def read(self) -> typing.Optional[ConnectionLog]:
        if self.last_flow is None:
            return None
        connection = ConnectionLog(self.last_flow)
        connection.add(self.last_segment)
        while True:
            self._readline()
            if self.last_flow is None or self.last_flow != connection.flow:
                return connection
            connection.add(self.last_segment)
        return connection

    def _readline(self):
        self.last_line = self.proc.stdout.readline()
        self.last_flow, self.last_segment = LineParser.parse_line(self.last_line)
        while self.last_line and self.last_flow is None:
            self.last_line = self.proc.stdout.readline()
            self.last_flow, self.last_segment = LineParser.parse_line(self.last_line)


class LineParser:
    # Neither Scapy or dpkt seem to handle TCP timestamps.  Who deals
    # with TCP timestamp nonsense anyway?  We do it using tcpdump.
    # 18:13:36.991039 IP 10.255.0.5.80 > 10.0.0.2.40049: Flags [S.], seq 706465395, ack 1477827212, win 65535, options [mss 1460,sackOK,TS val 2464404701 ecr 795743776,nop,wscale 7], length 0
    # 18:13:36.991064 IP 10.0.0.2.40049 > 10.255.0.5.80: Flags [.], ack 1, win 512, options [nop,nop,TS val 795743787 ecr 2464404701], length 0
    REGEX_LENGTH = r"length (?P<length>\d+)"
    REGEX_IP = (
        r"IP (?P<src>[\d\.]+)\.(?P<sport>\d+) > (?P<dst>[\d\.]+)\.(?P<dport>\d+):"
    )
    REGEX_SEQNUM = r"seq (?P<seq>\d+)"
    REGEX_TSTAMP = r"TS val (?P<tsval>\d+) ecr \d+"
    REGEX_FLAGS = r"Flags \[(?P<flags>[A-Z\.]+)\]"
    RE_LENGTH = re.compile(REGEX_LENGTH)
    RE_IP = re.compile(REGEX_IP)
    RE_SEQNUM = re.compile(REGEX_SEQNUM)
    RE_TSTAMP = re.compile(REGEX_TSTAMP)
    RE_FLAGS = re.compile(REGEX_FLAGS)

    @classmethod
    def parse_line(cls, line: str) -> typing.Union[tuple[None, None], tuple[FlowSpec, Segment]]:
        m = LineParser.RE_IP.search(line)
        if not m:
            logging.error("could not parse flowspec --- %s", line)
            return None, None
        src = ipaddress.IPv4Address(m.group("src"))
        sport = int(m.group("sport"))
        # if sport != 80:
            # the tcpdump subprocess filters for server packets
            # logging.info("packet not from port 80 --- %s", line)
            # return None, None

        dst = ipaddress.IPv4Address(m.group("dst"))
        dport = int(m.group("dport"))
        # dataclasses never do type conversion
        flow = FlowSpec(src, dst, sport, dport)

        m = LineParser.RE_LENGTH.search(line)
        if not m:
            logging.error("could not parse packet length --- %s", line)
            return None, None
        length = int(m.group("length"))

        m = LineParser.RE_FLAGS.search(line)
        if not m:
            logging.error("could not parse flags --- %s", line)
            return None, None
        flags = set(Flags(letter) for letter in m.group("flags"))

        m = LineParser.RE_SEQNUM.search(line)
        if not m:
            # ignoring packet with no data (may happen for FIN packets)
            assert length == 0
            return None, None
        seq = int(m.group("seq"))

        m = LineParser.RE_TSTAMP.search(line)
        if not m:
            logging.error("could not parse timestamp --- %s", line)
            return None, None
        tsval = int(m.group("tsval"))

        return flow, Segment(seq, tsval, flags)


def main():
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 35, 1 << 35))
    logging.basicConfig(
        filename="dumpcheck.log", format="%(message)s", level=logging.NOTSET
    )
    cnt = collections.Counter()

    parser = create_parser()
    opts = parser.parse_args()

    creader = ConnectionReader(opts.client_dump_fn, opts.server_network)
    sreader = ConnectionReader(opts.server_dump_fn, opts.server_network)
    outfd = open(opts.outfn, "w", encoding="utf8")
    outfd.write(ConnectionSummary.header_line())

    while True:
        cc = creader.read()
        sc = sreader.read()
        if cc is None:
            break
        cnt["connections"] += 1
        logging.debug("processing client ConnectionLog for %s", cc.flow)
        logging.debug("processing server ConnectionLog for %s", sc.flow)
        while sc.flow != cc.flow:
            logging.info("flow %s not observed on client side", sc.flow)
            logging.debug("processing server ConnectionLog for %s", cc.flow)
            sc = sreader.read()
            if sc is None:
                break
        if sc is None:
            break
        csum = ConnectionLog.compare_server_client(sc, cc, opts)
        outfd.write(f"{cc.flow} {csum.to_string(opts.mss)}\n")
        if Errors.DROPPED_PACKETS in csum.errors:
            logging.warning("it seems tcpdump dropped packets. results will be wrong.")

    # We ignore all connections on the server side after the client dump
    # is over. The plan is to only look at connections not in the first
    # and last minutes of the emulation.

    logging.info("processed %d connections", cnt["connections"])
    creader.close()
    sreader.close()


def create_parser() -> argparse.ArgumentParser:
    desc = """Process TCPdump traces to infer packet losses"""
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument(
        "--server-dump",
        dest="server_dump_fn",
        action="store",
        metavar="FILE",
        type=pathlib.Path,
        required=True,
        help="File containing tcpdump from the server",
    )
    parser.add_argument(
        "--client-dump",
        dest="client_dump_fn",
        action="store",
        metavar="FILE",
        type=pathlib.Path,
        required=True,
        help="File containing tcpdump from the client",
    )
    parser.add_argument(
        "--output",
        dest="outfn",
        action="store",
        metavar="FILE",
        type=pathlib.Path,
        required=True,
        help="File where output will be written",
    )
    parser.add_argument(
        "--server-network",
        dest="server_network",
        action="store",
        metavar="CIDR",
        type=ipaddress.IPv4Network,
        required=False,
        help="Network where servers are hosted (only server packets processed) [%(default)s]",
        default=ipaddress.IPv4Network("10.255.0.0/24"),
    )
    parser.add_argument(
        "--tcp-mss",
        dest="mss",
        action="store",
        metavar="BYTES",
        type=int,
        required=False,
        help="TCP maximum segment size (all segments but last assumed this size) [%(default)s]",
        default=1448,
    )
    return parser


if __name__ == "__main__":
    sys.exit(main())
