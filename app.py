from flask import Flask, request, jsonify
from flask_cors import CORS  # Import thư viện CORS
from services.packet_service import send_packet_logic

app = Flask(__name__)
CORS(app, resources={r"/send_packet": {"origins": "http://localhost:3000"}})  # Cho phép CORS với frontend

@app.route('/send_packet', methods=['POST'])
def send_packet():
    try:
        data = request.json
        response = send_packet_logic(data)
        return jsonify({"status": "success", "message": response})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

