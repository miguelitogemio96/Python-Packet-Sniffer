import socket
from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.tcp import TCP
from networking.pcap import Pcap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

def main():
    #realizamos las capturas en el archivo capture.pcap y la conf del socket
    pcap = Pcap('capture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    #recibimos trodos los paquetes....
    while True:
        raw_data, addr = conn.recvfrom(65535)
        #escribimos el paquete en el archivo para almacenarlo
        pcap.write(raw_data)
        #desmpaquetamos desde la primera capa
        eth = Ethernet(raw_data)

        #evaluamos si tiene es ipv4
        if eth.proto == 8:
            #pasamos a la segunda capa
            ipv4 = IPv4(eth.data)
            
            #evaluamos si es un paquete tcp
            if ipv4.proto == 6:
                #pasamos a la tercera capa
                tcp = TCP(ipv4.data)
                #vemos si pertenece al puerto 9000
                if tcp.src_port == 9000 or tcp.dest_port == 9000:
                    #desplegamos toda la informacion
                    print(TAB_1 + 'TCP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                    print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                    print(TAB_2 + 'Flags:')
                    print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                    print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))
                    #Mostramos si tiene aun mas datos
                    if len(tcp.data) > 0:
                        print(TAB_4 + '______________Este paquete contiene datos_________________\t')
    #terminamos la captura
    pcap.close()
main()
