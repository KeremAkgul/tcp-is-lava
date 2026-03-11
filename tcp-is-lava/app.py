from flask import Flask, render_template, request, jsonify
from scapy.all import IP, TCP, sr1, send
import random

app = Flask(__name__)

# Rastgele kaynak portu ve sequence numarası tutan durum sözlüğü
state = {
    "src_port": random.randint(1024, 65535),
    "seq": random.randint(1000, 5000),
    "ack": 0
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/send_packet', methods=['POST'])
def send_packet():
    data = request.json
    target_ip = data.get('ip')
    target_port = int(data.get('port'))
    flag = data.get('flag')
    
    ip_layer = IP(dst=target_ip)
    
    if flag == "SYN":
        # Yeni bağlantı için port ve seq yenile
        state["src_port"] = random.randint(1024, 65535)
        tcp_layer = TCP(sport=state["src_port"], dport=target_port, flags="S", seq=state["seq"])
        
        # Gönder ve ilk cevabı bekle (sr1)
        ans = sr1(ip_layer/tcp_layer, timeout=2, verbose=False)
        
        log_out = f"OUT: SYN -> {target_ip}:{target_port} (SPort: {state['src_port']}, Seq: {state['seq']})"
        log_in = "IN: Timeout - Yanıt gelmedi veya filtrelendi."
        
        if ans and ans.haslayer(TCP):
            if ans[TCP].flags == "SA" or ans[TCP].flags == 0x12: # SYN-ACK
                state["ack"] = ans[TCP].seq + 1
                state["seq"] += 1
                log_in = f"IN: SYN-ACK Geldi! <- (Seq: {ans[TCP].seq}, Ack: {ans[TCP].ack})"
            else:
                log_in = f"IN: Beklenmeyen bayrak (Flags: {ans[TCP].flags})"
                
        return jsonify({"log_out": log_out, "log_in": log_in})

    elif flag == "ACK":
        tcp_layer = TCP(sport=state["src_port"], dport=target_port, flags="A", seq=state["seq"], ack=state["ack"])
        send(ip_layer/tcp_layer, verbose=False)
        
        log_out = f"OUT: ACK -> {target_ip}:{target_port} (Seq: {state['seq']}, Ack: {state['ack']})"
        return jsonify({"log_out": log_out, "log_in": "IN: Bağlantı kuruldu (ESTABLISHED)."})

    elif flag == "FIN":
        tcp_layer = TCP(sport=state["src_port"], dport=target_port, flags="FA", seq=state["seq"], ack=state["ack"])
        send(ip_layer/tcp_layer, verbose=False)
        
        log_out = f"OUT: FIN -> {target_ip}:{target_port} (Bağlantı kapatılıyor)"
        return jsonify({"log_out": log_out, "log_in": "IN: Bekleniyor..."})

    return jsonify({"log_out": "HATA", "log_in": ""})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=2000)