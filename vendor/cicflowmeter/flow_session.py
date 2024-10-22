import os
import sys

from scapy.packet import Packet
from scapy.sessions import DefaultSession

from .constants import EXPIRED_UPDATE, GARBAGE_COLLECT_PACKETS
from .features.context import PacketDirection, get_packet_flow_key
from .flow import Flow
from .utils import get_logger
from .writer import output_writer_factory

current_project_directory = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(current_project_directory)

from module.util import get_ip_address


class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    verbose = False
    fields = None
    output_mode = None
    output = None
    my_ip_addresses = None

    def __init__(self, *args, **kwargs):
        self.flows: dict[tuple, Flow] = {}
        self.logger = get_logger(self.verbose)
        self.packets_count = 0
        self.output_writer = output_writer_factory(self.output_mode, self.output)

        if self.my_ip_addresses is None:
            self.my_ip_addresses = [get_ip_address()]

        self.my_ip_addresses = set(self.my_ip_addresses)

        super(FlowSession, self).__init__(*args, **kwargs)

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
        self.garbage_collect(None)
        del self.output_writer
        return super(FlowSession, self).toPacketList()

    def on_packet_received(self, pkt: Packet):
        count = 0
        direction = PacketDirection.FORWARD

        if "TCP" not in pkt and "UDP" not in pkt:
            return

        try:
            # Creates a key variable to check
            packet_flow_key = get_packet_flow_key(pkt, direction)
            flow = self.flows.get((packet_flow_key, count))
        except Exception:
            return

        self.packets_count += 1
        self.logger.debug(f"Packet {self.packets_count}: {pkt}")

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(pkt, direction)
            flow = self.flows.get((packet_flow_key, count))

        if flow is None:
            # If no flow exists and the packet has FIN flag then early collect flow and continue
            if "TCP" in pkt and pkt["TCP"].flags.F:
                return

            # 만약 dst IP가 본인 IP가 아니라면 처리 안함
            if pkt["IP"].dst not in self.my_ip_addresses:
                return

            # If no flow exists create a new flow
            direction = PacketDirection.FORWARD
            flow = Flow(pkt, direction)
            packet_flow_key = get_packet_flow_key(pkt, direction)
            self.flows[(packet_flow_key, count)] = flow

        elif (pkt.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            # If the packet exists in the flow but the packet is sent
            # after too much of a delay than it is a part of a new flow.
            expired = EXPIRED_UPDATE
            while (pkt.time - flow.latest_timestamp) > expired:
                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    flow = Flow(pkt, direction)
                    self.flows[(packet_flow_key, count)] = flow
                    break
        elif "TCP" in pkt and pkt["TCP"].flags.F:
            # If it has FIN flag then early collect flow and continue
            flow.add_packet(pkt, direction)
            self.garbage_collect(pkt.time)
            # self.output_writer.write(flow.get_data(self.fields))
            # packet_flow_key = get_packet_flow_key(pkt, direction)
            # k = (packet_flow_key, count)
            # del self.flows[k]
            return

        flow.add_packet(pkt, direction)

        if self.packets_count % GARBAGE_COLLECT_PACKETS == 0 or flow.duration > 120:
            self.garbage_collect(pkt.time)

    def get_flows(self):
        return self.flows.values()

    def garbage_collect(self, latest_time) -> None:
        # TODO: Garbage Collection / Feature Extraction should have a separate thread
        for k in list(self.flows.keys()):
            flow = self.flows.get(k)

            if not flow or (
                latest_time is not None
                and latest_time - flow.latest_timestamp < EXPIRED_UPDATE
                and flow.duration < 90
            ):
                continue

            self.output_writer.write(flow.get_data(self.fields))

            if k in self.flows:
                del self.flows[k]

            self.logger.debug(f"Flow Collected! Remain Flows = {len(self.flows)}")
