import math
import dpkt
import struct

from typing import Dict, List
from pprint import pformat
from collections import OrderedDict
from datetime import datetime as dt

def get_str_attr(data: bytes, sep: str, format:str, start: int, end: int):
    return sep.join(map(str, struct.unpack(format, data[start:end+1])))

def get_int_attr(data: bytes, format:str, start: int, end: int):
    return struct.unpack(format, data[start:end+1])[0]

sender_ip = '130.245.145.12'
receiver_ip = '128.208.2.198'

class Packet:
    def __init__(self, data: bytes, timestamp:float):
        # Use formats as per https://docs.python.org/3/library/struct.html
        self.src_ip: str = get_str_attr(data, '.', 'BBBB', 26, 29)
        self.dest_ip: str = get_str_attr(data, '.', 'BBBB', 30, 33)
        self.src_port: str = get_str_attr(data, '', '>H', 34, 35)
        self.dest_port: str = get_str_attr(data, '', '>H', 36, 37)
        self.seq_num: int = get_int_attr(data, '>I', 38, 41)
        self.ack_num: int = get_int_attr(data, '>I', 42, 45)
        self.tcp_header_len: int = 8 * (get_int_attr(data, '>B', 46, 46) // 32)
        
        flags = '{0:08b}'.format(get_int_attr(data, '>B', 47, 47))
        self.ack: int = int(flags[3])
        self.psh: int = int(flags[4])
        self.syn: int = int(flags[6])
        self.fin: int = int(flags[7])

        self.window_size: int = get_int_attr(data, '>H', 48, 49)
        self.size: int = len(data)
        # Total header size = 14 (Ethernet) + 20 (IP) + TCP Header Len
        self.payload_size: int = len(data[(14 + 20 + self.tcp_header_len):])
        self.timestamp: float = timestamp

        if self.syn == 1 and self.ack == 0:
            kind = get_int_attr(data, '>B', 54, 54)
            if kind == 2:
                self.mss: int = get_int_attr(data, '>H', 56, 57)
            self.scaling_window_size: int = int(math.pow(2, get_int_attr(data, '>B', 73, 73)))
    
    def __repr__(self):
        return pformat(vars(self), indent=4, width=1)

class Flow:
    def __init__(self, id: int, sender_port: str, receiver_port: str):
        self.id: int = id
        self.sender_port: str = sender_port
        self.receiver_port: str = receiver_port
        self.total_packets: int = 0
        self.total_sender_packets: int = 0
        self.total_receiver_packets: int = 0

        self.packets: List[Packet] = []
        self.sender_indices: List[int] = []
        self.receiver_indices: List[int] = []
    
    def __repr__(self):
        return pformat(vars(self), indent=4, width=1)
    
    def set_mss(self, mss: int):
        self.mss = mss
    
    def set_scaling_window(self, scaling_window_size: int):
        self.scaling_window_size = scaling_window_size
    
    def set_loss_rate(self, loss_rate: float):
        self.loss_rate = loss_rate
    
    def set_rtt(self, rtt: float):
        self.rtt = rtt
    
    def set_packets_lost(self, packets_lost: int):
        self.packets_lost = packets_lost

class TCPAnalyzer:
    def __init__(self, pcap: dpkt.pcap.Reader):
        self.pcap = pcap
        self.flows: Dict[int, Flow] = OrderedDict()
    
    def update_sender_args(self, flow: Flow, packet: Packet):
        flow.packets.append(packet)
        flow.total_packets += 1
        flow.total_sender_packets += 1
        flow.sender_indices.append(flow.total_packets - 1)
    
    def update_receiver_args(self, flow: Flow, packet: Packet):
        flow.packets.append(packet)
        flow.total_packets += 1
        flow.total_receiver_packets += 1
        flow.receiver_indices.append(flow.total_packets - 1)
    
    def init_flow(self, flow_id: int, packet: Packet) -> Flow:
        flow = Flow(flow_id, packet.src_port, packet.dest_port)
        flow.set_mss(packet.mss)
        flow.set_scaling_window(packet.scaling_window_size)
        self.update_sender_args(flow, packet)
        return flow
    
    def init_flows(self):
        flow_id = 1
        port_to_flow_id_map = {}
        for timestamp, data in self.pcap:
            packet = Packet(data, timestamp)
            if packet.src_ip == sender_ip:
                flow_number = port_to_flow_id_map.get(packet.src_port)
                if flow_number:
                    flow = self.flows.get(flow_number)
                    self.update_sender_args(flow, packet)
                    self.flows[flow_number] = flow
                else:
                    flow = self.init_flow(flow_id, packet)
                    self.flows[flow_id] = flow
                    port_to_flow_id_map[packet.src_port] = flow_id
                    flow_id += 1
            else:
                flow_number = port_to_flow_id_map.get(packet.dest_port)
                flow = self.flows.get(flow_number)
                self.update_receiver_args(flow, packet)
                self.flows[flow_number] = flow
        print("Flow 1 # packets: {}, Flow 2 # packets: {}, Flow 3 # packets: {}\n".format(
            self.flows[1].total_packets, self.flows[2].total_packets, self.flows[3].total_packets))
    
    def num_conns_a_1(self):
        num_conn, num_open = 0, 0
        ports = []
        for _, flow in self.flows.items():
            ports.append(flow.sender_port)
            for packet in flow.packets:
                if packet.syn == 1 and packet.ack == 1:
                    num_open += 1
                    num_conn += 1
                if packet.fin == 1 and packet.src_ip == receiver_ip:
                    num_open -= 1
        print('-'*30 + 'PART A - 1)' + '-'*30)
        print('Number of TCP Connections initiated from {} = {}, on ports {}\n'.format(sender_ip, num_conn, ','.join(ports)))
        if num_open != 0:
            print("Not all connections were closed\n")
    
    def flow_analysis_a_2(self):
        print('-'*30 + 'PART A - 2)' + '-'*30)

        # Part 2a) For the first 2 transactions after the TCP connection is set up (from sender to receiver), get the values of the 
        # Sequence number, Ack number, and Receive Window size
        print('-'*10 + '2a)' + '-'*10)
        for flow_id, flow in self.flows.items():
            i = 1
            print("::"*10 + "Flow {}".format(flow_id) + "::"*10)
            while i <= 2:
                send_packet = flow.packets[flow.sender_indices[i+1]]
                receive_packet = flow.packets[flow.receiver_indices[i]]
                print("Transaction {}:".format(i))
                print("Sender {}: Sequence Number = {}, Ack Number = {}, Calculated Receive Window Size = {}".format(
                    sender_ip, send_packet.seq_num, send_packet.ack_num, send_packet.window_size * flow.scaling_window_size
                ))
                print("Receiver {}: Sequence Number = {}, Ack Number = {}, Calculated Receive Window Size = {}\n".format(
                    receiver_ip, receive_packet.seq_num, receive_packet.ack_num, receive_packet.window_size * flow.scaling_window_size
                ))
                i += 1
        
        # Part 2b) Compute the throughput at the receiver
        print('-'*10 + '2b)' + '-'*10)
        for flow_id, flow in self.flows.items():
            total_sender_bytes = 0
            for sender_index in flow.sender_indices:
                total_sender_bytes += flow.packets[sender_index].size
            first_ts = flow.packets[0].timestamp
            last_ts = flow.packets[-1].timestamp
            total_time = (dt.fromtimestamp(last_ts) - dt.fromtimestamp(first_ts)).total_seconds()
            throughput = total_sender_bytes / total_time
            print("Flow {} Throughput = {} MBps".format(flow_id, round(throughput / 1000000, 3)))
        
        # Part 2c) Compute the loss rate for each flow. Loss rate is the number of packets not received 
        # divided by the number of packets sent
        print('\n' + '-'*10 + '2c)' + '-'*10)
        for flow_id, flow in self.flows.items():
            dup_seq_count = {}
            for sender_index in flow.sender_indices:
                if dup_seq_count.get(flow.packets[sender_index].seq_num) is not None:
                    dup_seq_count[flow.packets[sender_index].seq_num] = dup_seq_count.get(flow.packets[sender_index].seq_num) + 1
                else:
                    dup_seq_count[flow.packets[sender_index].seq_num] = 0
            
            num_lost = 0
            for dup_seq_nums in dup_seq_count.values():
                num_lost += dup_seq_nums
            
            # subtract 1 because the psh/ack packet after the handshake will have same sequence number as the last packet in the TCP handshake
            num_lost -= 1
            loss_rate = round(num_lost / flow.total_sender_packets, 7)
            flow.set_loss_rate(loss_rate)
            flow.set_packets_lost(num_lost)
            print("Flow {}: Number of lost sender packets = {}, Loss Rate = {}".format(flow_id, num_lost, loss_rate))
        
        # Part 2d) Estimate the average RTT. Now compare your empirical throughput from (b) and the theoretical throughput
        print('\n' + '-'*10 + '2d)' + '-'*10)
        for flow_id, flow in self.flows.items():
            sender_seq_dict, receiver_ack_dict, dup_seq_dict = {}, {}, {}
            for sender_index in flow.sender_indices:
                if sender_seq_dict.get(flow.packets[sender_index].seq_num):
                    dup_seq_dict[flow.packets[sender_index].seq_num] = True
                else:
                    sender_seq_dict[flow.packets[sender_index].seq_num] = flow.packets[sender_index].timestamp
            for receiver_index in flow.receiver_indices:
                receiver_ack_dict[flow.packets[receiver_index].ack_num] = flow.packets[receiver_index].timestamp
            
            # For calculating avg RTT, we can exclude retransmitted packets from the sample (Karn's algorithm) 
            for seq_num in dup_seq_dict.keys():
                sender_seq_dict.pop(seq_num)
            
            total_rtt, acks = 0, 0
            for ack_num, ack_ts in receiver_ack_dict.items():
                if sender_seq_dict.get(ack_num):
                    acks += 1
                    total_rtt += (dt.fromtimestamp(ack_ts) - dt.fromtimestamp(sender_seq_dict.get(ack_num))).total_seconds()
            avg_rtt = round(total_rtt / acks, 5)
            flow.set_rtt(avg_rtt)
            if flow.loss_rate != 0:
                theoretical_throughput = round(((1.5 ** 0.5) * flow.mss) / (avg_rtt * (flow.loss_rate ** 0.5) * 1000000), 4)
            else:
                theoretical_throughput = float('+inf')
            print("Flow {}: Avg RTT = {}, Theoretical Throughput = {} MBps".format(flow_id, avg_rtt, theoretical_throughput))
    
    def congestion_window_b_1(self):
        print('\n\n' + '-'*30 + 'PART B - 1)' + '-'*30)
        for flow_id, flow in self.flows.items():
            initial_time = flow.packets[0].timestamp
            # Start with waiting for 2nd ACK, since first one was received during TCP handshake
            acks_recvd, cwin_byte_size = 1, 0
            cwin_10 = []
            for sender_index in flow.sender_indices[2:]:
                cwin_packet = flow.packets[sender_index]
                relative_time = (dt.fromtimestamp(cwin_packet.timestamp) - dt.fromtimestamp(initial_time)).total_seconds()
                # Calculate the congestion window size until next ACK is received. It is estimated that an ACK is recieved after every RTT,
                # so we calculate cumulative bytes sent between 2 RTTs to be the same as the congestion window size for that window.
                if relative_time <= (flow.rtt * (acks_recvd + 1)):
                    cwin_byte_size += cwin_packet.size
                else:
                    # Calculate only first 10 Congestion Window sizes
                    if len(cwin_10) < 10:
                        cwin_10.append(cwin_byte_size)
                        acks_recvd += 1
                        cwin_byte_size = cwin_packet.size
                    else:
                        break
            print("Flow {}".format(flow_id))
            print("First 10 congestion windows (after handshake): {}".format(cwin_10))
            print("Growth Rate of Congestion Window: {}".format([round(j/i, 3) for i, j in zip(cwin_10[:-1], cwin_10[1:])]))
    
    def triple_dup_ack_b_2(self):
        print('\n' + '-'*30 + 'PART B - 2)' + '-'*30)
        for flow_id, flow in self.flows.items():
            sender_seq_dict: Dict[int, List[Packet]] = {}
            receiver_ack_dict: Dict[int, List[Packet]] = {}
            for sender_index in flow.sender_indices[2:]:
                sender_packet = flow.packets[sender_index]
                if sender_seq_dict.get(sender_packet.seq_num):
                    sender_seq_dict.get(sender_packet.seq_num).append(sender_packet)
                else:
                    sender_seq_dict[sender_packet.seq_num] = [sender_packet]
            for receiver_index in flow.receiver_indices[1:]:
                receiver_packet = flow.packets[receiver_index]
                if receiver_ack_dict.get(receiver_packet.ack_num):
                    receiver_ack_dict.get(receiver_packet.ack_num).append(receiver_packet)
                else:
                    receiver_ack_dict[receiver_packet.ack_num] = [receiver_packet]
            
            # Calculate total number of retransmissions that have occurred
            dup_seq_dict: Dict[int, List[Packet]] = {}
            for seq_num, packets in sender_seq_dict.items():
                if len(packets) > 1:
                    dup_seq_dict[seq_num] = packets

            triple_dup_acks = 0
            for seq_num, packets in dup_seq_dict.items():
                if receiver_ack_dict.get(seq_num) and len(receiver_ack_dict.get(seq_num)) >= 3:
                    triple_dup_acks += 1
            
            print('Flow {}'.format(flow_id))
            print('Number of Triple Duplicate ACKs = {}'.format(triple_dup_acks))
            print('Number of Timeouts = {}\n'.format(flow.packets_lost - triple_dup_acks))
            

if __name__ == '__main__':
    f = open('assignment2.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)

    tcp_analyzer = TCPAnalyzer(pcap)
    tcp_analyzer.init_flows()

    # Part A
    tcp_analyzer.num_conns_a_1()
    tcp_analyzer.flow_analysis_a_2()

    # Part B
    tcp_analyzer.congestion_window_b_1()
    tcp_analyzer.triple_dup_ack_b_2()
