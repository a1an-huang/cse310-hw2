# Alan Huang 113443530
# CSE310 Programming Assignment #2

import socket
import dpkt

file = open('assignment2.pcap', 'rb')
pcap = dpkt.pcap.Reader(file)

count = 0
ack_count = 0
ip_port = {}
sender_port = {}
receiver_port = {}
transactions = {}
throughput = {}
sequence = {}
ack = {}
triple_ack = {}
total_retransmission = {}
triple_dupe_ack = {}
triple_dupe = {}

for ts, buf in pcap:
    ethernet = dpkt.ethernet.Ethernet(buf)

    src_ip = ethernet.data.src
    dest_ip = ethernet.data.dst
    str_src_ip = socket.inet_ntoa(src_ip)
    str_dest_ip = socket.inet_ntoa(dest_ip)

    ip = ethernet.data
    tcp = ip.data

    if tcp.ack == 0:
        throughput[tcp.sport] = [0, 0, 0]
        ip_port[count] = [tcp.sport, str_src_ip, tcp.dport, str_dest_ip]
        sender_port[tcp.sport] = 1
        receiver_port[tcp.dport] = 1
        count += 1

    elif tcp.dport in receiver_port and tcp.sport in sender_port:
        # print(sender_port[tcp.sport], ts)
        if sender_port[tcp.sport] == 1:

            throughput[tcp.sport][1] = ts

        throughput[tcp.sport][0] += ip.len
        throughput[tcp.sport][2] = ts

        if sender_port[tcp.sport] < 3:
            if tcp.sport not in transactions:
                transactions[tcp.sport] = [[tcp.seq, tcp.ack, tcp.win]]
                sender_port[tcp.sport] += 1
            elif tcp.ack != transactions[tcp.sport][0][1] or tcp.seq != transactions[tcp.sport][0][0]:
                transactions[tcp.sport].append([tcp.seq, tcp.ack, tcp.win])
                sender_port[tcp.sport] += 1

    if tcp.sport in receiver_port and tcp.dport in sender_port:
        if tcp.ack not in triple_ack:
            triple_ack[tcp.ack] = 1
            # print(triple_ack[tcp.ack])
        else:
            triple_ack[tcp.ack] += 1

        if triple_ack[tcp.ack] > 3:
            triple_dupe_ack[tcp.ack] = 1

    if tcp.sport in sender_port and tcp.dport in receiver_port:
        if tcp.seq in triple_dupe_ack:
            if tcp.sport not in triple_dupe:
                triple_dupe[tcp.sport] = 1
            else:
                triple_dupe[tcp.sport] += 1

        if tcp.seq not in sequence:
            sequence[tcp.seq] = 1
        else:
            if tcp.sport not in total_retransmission:
                total_retransmission[tcp.sport] = 1
            else:
                total_retransmission[tcp.sport] += 1

print("total number of flows : ", count)
for i in range(count):
    print("The port numbers and IP addresses of flow ",
          i, "is : ", ip_port[i])

print("first two transaction in the flow")
for transaction in transactions:
    print(transactions[transaction])

t_counter = 1
for tp in throughput:
    total_time = throughput[tp][2] - throughput[tp][1]
    print(total_time, throughput[tp][2], throughput[tp][1])
    print("Total bytes of data sent by flow " + str(t_counter) + " are : " +
          str(throughput[tp][0]) + " and the throughput is : " + str(throughput[tp][0] / total_time))
    t_counter += 1

for sender in sender_port:
    if sender in triple_dupe:
        print("The number of retransmission due to triple duplicate for the flow with port number " +
              str(sender) + " is " + str(triple_dupe[sender]))
        if sender in total_retransmission:
            print("The number of retransmission due to timeout is " +
                  str(total_retransmission[sender] - triple_dupe[sender]))
    else:
        if sender in total_retransmission:
            print("The number of retransmission due to triple duplicate for the flow with port number " +
                  str(sender) + " is zero")
            print("The number of retransmission due to timeout is " +
                  str(total_retransmission[sender]))
