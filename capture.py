import json
import time
from scapy.all import sniff, Raw, IP, TCP
from pymongo import MongoClient
from flask import Flask, jsonify
from flask_cors import CORS
from urllib.parse import quote_plus

username = "adnankstheredteamlabs"
password = "Adnan@66202"
# Make sure to replace with your cluster name and database name
cluster_name = "cluster0"
database_name = "network_packets"

# URL-encode the username and password
username_encoded = quote_plus(username)
password_encoded = quote_plus(password)

# Construct the MongoDB connection URI
MONGO_URI = f"mongodb+srv://{username_encoded}:{password_encoded}@{cluster_name}.qrppz7h.mongodb.net/{database_name}?retryWrites=true&w=majority"

client = MongoClient(MONGO_URI)
db = client[database_name]
packets_collection = db['packets']
http_collection = db['http_packets']

# Flask app to provide API endpoints
app = Flask(__name__)
CORS(app)  # Allow CORS for all routes

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        packet_info = {
            'timestamp': time.time(),
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'protocol': packet.proto,
            'length': len(packet),
            'raw_data': bytes(packet).hex()
        }
        
        # Check for TCP/UDP layers to extract ports
        if packet.haslayer(TCP):
            packet_info['src_port'] = packet[TCP].sport
            packet_info['dst_port'] = packet[TCP].dport
            packet_info['protocol_name'] = 'TCP'

            # Check for HTTP POST requests
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                if b"POST" in payload:
                    http_info = {
                        'timestamp': time.time(),
                        'src_ip': ip_layer.src,
                        'dst_ip': ip_layer.dst,
                        'src_port': packet[TCP].sport,
                        'dst_port': packet[TCP].dport,
                        'method': 'POST',
                        'payload': payload.decode(errors='ignore')  # Decode payload
                    }
                    http_collection.insert_one(http_info)
                    print(f"HTTP POST request captured and stored: {http_info}")

        # Store the packet in MongoDB
        packets_collection.insert_one(packet_info)
        print(f"Packet captured and stored: {packet_info}")

# Sniffing function
def start_sniffing():
    sniff(prn=packet_callback, store=0)

# API endpoint to get packet data
@app.route('/api/packets', methods=['GET'])
def get_packets():
    packets = list(packets_collection.find().sort("timestamp", -1).limit(100))  # Fetch last 100 packets
    for packet in packets:
        packet['_id'] = str(packet['_id'])
    return jsonify(packets)

# API endpoint to get HTTP packet data
@app.route('/api/http_packets', methods=['GET'])
def get_http_packets():
    http_packets = list(http_collection.find().sort("timestamp", -1).limit(100))  # Fetch last 100 HTTP packets
    for packet in http_packets:
        packet['_id'] = str(packet['_id'])
    return jsonify(http_packets)

# API endpoint to get packet statistics
@app.route('/api/stats', methods=['GET'])
def get_packet_stats():
    pipeline = [
        {
            '$group': {
                '_id': '$protocol_name',
                'count': {'$sum': 1}
            }
        }
    ]
    stats = list(packets_collection.aggregate(pipeline))
    return jsonify(stats)

if __name__ == "__main__":
    from multiprocessing import Process
    p = Process(target=start_sniffing)
    p.start()
    app.run(host='0.0.0.0', port=5000, debug=True)
    p.join()
