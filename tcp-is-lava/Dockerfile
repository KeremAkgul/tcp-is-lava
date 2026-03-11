FROM python:3.9-slim

# Scapy ve güvenlik duvarı kuralları için gerekli araçlar
RUN apt-get update && apt-get install -y tcpdump libpcap-dev iptables && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Gerekli Python kütüphaneleri
RUN pip install flask scapy

COPY . .

EXPOSE 2000

# Kernel'in RST paketlerini dropla ve Flask'ı başlat
CMD bash -c "iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP && python app.py"