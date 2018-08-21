from scapy.all import *
import zlib
import uuid
import re
import sys

rutaArchPCAP='./192.168.252.93_capture.pcap'
opcion = 0
archPCAP = rdpcap(rutaArchPCAP)



#Funciones
def historial():
    # Itero las sesiones en el tráfico de red.
    for session in archPCAP:
        # Itero los paquetes de la sesión
        for packet in session:
            try:
                # Si el paquete tiene la capa de DNS, entonces accedo 
                # e imprimo la query hecha al servidor DNS
                if(packet[DNS]):
                    print(packet[DNS].qd.qname)
            except IndexError:
                pass

#Para ver el historial
if(opcion == 0):
    historial()