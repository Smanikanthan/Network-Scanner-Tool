#!/usr/bin/env python3
import sys, socket, threading
from queue import Queue
from ipaddress import ip_network
from scapy.all import ARP, Ether, srp, conf

conf.verb = 0

def generate_ips(cidr):
    return [str(ip) for ip in ip_network(cidr, strict=False).hosts()]

def worker(q, results, timeout=1):
    while True:
        ip = q.get()
        if ip is None:
            q.task_done()
            break
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
            answered, _ = srp(pkt, timeout=timeout, retry=0)
            for _, rcv in answered:
                mac = rcv.hwsrc
                try:
                    host = socket.gethostbyaddr(ip)[0]
                except Exception:
                    host = ""
                results.append((ip, mac, host))
        except Exception:
            pass
        finally:
            q.task_done()

def scan_network(cidr, threads=50, timeout=1):
    ips = generate_ips(cidr)
    q, results = Queue(), []
    workers = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(q, results, timeout))
        t.daemon = True
        t.start()
        workers.append(t)
    for ip in ips:
        q.put(ip)
    q.join()
    for _ in workers:
        q.put(None)
    for t in workers:
        t.join()
    return results

def print_table(results):
    print(f"{'IP':<16} {'MAC':<20} {'HOSTNAME'}")
    print("-" * 60)
    for ip, mac, host in sorted(results, key=lambda x: x[0]):
        print(f"{ip:<16} {mac:<20} {host}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: sudo python3 Netscann.py <network/cidr>")
        sys.exit(1)
    cidr = sys.argv[1]
    print(f"Scanning {cidr} ... (this may take a bit)")
    res = scan_network(cidr, threads=50, timeout=1)
    print_table(res)
