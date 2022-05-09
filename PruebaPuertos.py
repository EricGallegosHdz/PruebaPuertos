#test de ips

import os
import threading

received = []

def search(ip_address):
    comando = "ping "+ip_address+" -n 1"
    response = os.popen(comando).read()
    if "1 received" in response:
        print("Encontrado en: ",ip_address)
        received.append(ip_address)

for ip in range(1,254):
    current_ip = "192.168.0."+str(ip)
    print("Analizando la ip:", current_ip)
    #search(current_ip)

    run = threading.Thread(target=search , args = (current_ip,))
    run.start()

for x in received:
    nm = nmap.PortScanner()
    results = nm.scan(ip)
    print("Host : %s (%s)" % (host))
    print("State : %s" % nm[host].state())
    for proto in nm[host].all_protocols():
        print("-------")
        print("Protocol : %s" % proto)

        lport = nm[host][proto].keys()
        lport.sort()
        for port in lport:
            print("port : %s\tstate : %s" % (port, nm[host][proto][port]["state"]))
