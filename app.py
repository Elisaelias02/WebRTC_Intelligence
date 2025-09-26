from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import requests
import json
import hashlib
import uuid
import os
import re

app = Flask(__name__)

# Configuración de base de datos
db_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database')
os.makedirs(db_dir, exist_ok=True)

db_path = os.path.join(db_dir, 'ip_intel.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy()

# Modelo de base de datos mejorado
class IPIntelligence(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = db.Column(db.String(50))
    real_ip = db.Column(db.String(45), nullable=False)
    vpn_ip = db.Column(db.String(45))
    client_ip = db.Column(db.String(45))
    public_ip = db.Column(db.String(45))  # IP pública obtenida por servicios
    stun_ips = db.Column(db.Text)  # JSON de IPs descubiertas por STUN
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))
    isp = db.Column(db.String(200))
    asn = db.Column(db.String(100))
    user_agent = db.Column(db.Text)
    ice_candidates = db.Column(db.Text)
    fingerprint_hash = db.Column(db.String(64))
    threat_level = db.Column(db.String(20), default='LOW')
    is_corporate = db.Column(db.Boolean, default=False)
    vpn_detected = db.Column(db.Boolean, default=False)
    vm_detected = db.Column(db.Boolean, default=False)
    vm_type = db.Column(db.String(50))
    vm_confidence = db.Column(db.Integer, default=0)
    timing_analysis = db.Column(db.Text)  # JSON de análisis de timing
    vpn_suspicion = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def initialize_database():
    """Inicializar base de datos con manejo de errores mejorado"""
    try:
        test_file = os.path.join(db_dir, 'test_write.tmp')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        
        db.init_app(app)
        
        with app.app_context():
            db.create_all()
            print(f"Database initialized successfully at: {db_path}")
            
    except PermissionError:
        print(f" Permission denied. Cannot write to {db_dir}")
        print("Try running: sudo chmod 755 database/")
        exit(1)
    except Exception as e:
        print(f" Database initialization failed: {str(e)}")
        exit(1)

class GeoIntelligence:
    @staticmethod
    def analyze_ip(ip):
        """Análisis geográfico mejorado con múltiples servicios"""
        services = [
            {'url': f'https://ipapi.co/{ip}/json/', 'type': 'ipapi'},
            {'url': f'http://ip-api.com/json/{ip}', 'type': 'ipapi_com'}
        ]
        
        for service in services:
            try:
                response = requests.get(service['url'], timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    
                    if service['type'] == 'ipapi':
                        return {
                            'country': data.get('country_name', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'latitude': data.get('latitude'),
                            'longitude': data.get('longitude'),
                            'isp': data.get('org', 'Unknown'),
                            'asn': data.get('asn', 'Unknown'),
                            'service': 'ipapi.co'
                        }
                    elif service['type'] == 'ipapi_com':
                        return {
                            'country': data.get('country', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'latitude': data.get('lat'),
                            'longitude': data.get('lon'),
                            'isp': data.get('isp', 'Unknown'),
                            'asn': data.get('as', 'Unknown'),
                            'service': 'ip-api.com'
                        }
                        
            except Exception as e:
                print(f"Geo service {service['url']} failed: {str(e)}")
                continue
        
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': None,
            'longitude': None,
            'isp': 'Unknown',
            'asn': 'Unknown',
            'service': 'none'
        }

class ThreatAnalyzer:
    @staticmethod
    def analyze_threat_level(ip, user_agent, asn, fingerprint_data, timing_data):
        """Análisis avanzado de amenazas con detección de VM y VPN mejorada"""
        threat_level = 'LOW'
        is_corporate = False
        vpn_detected = False
        vm_detected = False
        vpn_suspicion = False
        
        # Detectar redes corporativas expandidas
        corporate_indicators = [
            'GOOGLE', 'MICROSOFT', 'AMAZON', 'FACEBOOK', 'APPLE', 'ORACLE', 
            'IBM', 'CISCO', 'INTEL', 'NVIDIA', 'TESLA', 'NETFLIX', 'UBER',
            'TWITTER', 'LINKEDIN', 'ADOBE', 'SALESFORCE', 'ZOOM'
        ]
        if asn:
            asn_upper = str(asn).upper()
            for indicator in corporate_indicators:
                if indicator in asn_upper:
                    is_corporate = True
                    threat_level = 'MEDIUM'
                    break
        
        # Detectar VPNs - Lista muy expandida
        vpn_indicators = [
            'VPN', 'PROXY', 'TOR', 'MULLVAD', 'NORDVPN', 'EXPRESSVPN', 
            'SURFSHARK', 'CYBERGHOST', 'PRIVATE INTERNET ACCESS', 'PIA',
            'TUNNELBEAR', 'WINDSCRIBE', 'PROTONVPN', 'HOTSPOT SHIELD',
            'HIDE MY ASS', 'IPVANISH', 'VYPR', 'PERFECT PRIVACY',
            'DATACENTER', 'HOSTING', 'CLOUD', 'SERVER', 'VIRTUAL',
            'DIGITAL OCEAN', 'LINODE', 'VULTR', 'OVH', 'HETZNER',
            'AWS', 'AZURE', 'GCP', 'CLOUDFLARE', 'FASTLY',
            'HOSTINGER', 'GODADDY', 'NAMECHEAP', 'CONTABO'
        ]
        
        if asn:
            asn_upper = str(asn).upper()
            for indicator in vpn_indicators:
                if indicator in asn_upper:
                    vpn_detected = True
                    threat_level = 'HIGH'
                    break
        
        # Detectar máquinas virtuales del fingerprint
        if fingerprint_data and 'virtualization' in fingerprint_data:
            vm_data = fingerprint_data['virtualization']
            if vm_data.get('isVM', False):
                vm_detected = True
                if threat_level == 'LOW':
                    threat_level = 'MEDIUM'
                print(f"🖥️ VM DETECTED: {vm_data.get('vmType', 'Unknown')} - Confidence: {vm_data.get('confidence', 0)}%")
        
        # Analizar timing data para sospechas de VPN
        if timing_data:
            suspicious_count = sum(1 for t in timing_data if t.get('suspiciousDelay', False))
            if suspicious_count >= len(timing_data) / 2:  # Si más de la mitad son sospechosos
                vpn_suspicion = True
                if not vpn_detected:  # Solo aumentar si no se detectó VPN por otros medios
                    threat_level = 'MEDIUM'
        
        return threat_level, is_corporate, vpn_detected, vm_detected, vpn_suspicion

    @staticmethod
    def determine_real_vs_vpn_ip(client_ip, webrtc_ips, stun_ips, public_ip, geo_data_map):
        """
        Lógica avanzada para determinar IP real vs VPN
        """
        all_ips = []
        
        # Recopilar todas las IPs únicas
        if client_ip:
            all_ips.append(client_ip)
        if public_ip:
            all_ips.append(public_ip)
        if webrtc_ips:
            all_ips.extend(webrtc_ips)
        if stun_ips:
            all_ips.extend(stun_ips)
        
        # Eliminar duplicados manteniendo el orden
        unique_ips = []
        seen = set()
        for ip in all_ips:
            if ip and ip not in seen:
                unique_ips.append(ip)
                seen.add(ip)
        
        if not unique_ips:
            return client_ip or 'Unknown', None
        
        # Analizar cada IP
        ip_scores = {}
        for ip in unique_ips:
            score = 0
            geo = geo_data_map.get(ip, {})
            isp = geo.get('isp', '').upper()
            
            # Scoring system
            if ThreatAnalyzer.is_residential_ip(isp):
                score += 100  # Muy probable que sea real
            elif ThreatAnalyzer.is_mobile_ip(isp):
                score += 90   # Probable que sea real
            elif ThreatAnalyzer.is_datacenter_ip(isp):
                score -= 50   # Probable VPN
            
            # Bonus por ser IP pública obtenida por servicios
            if ip == public_ip:
                score += 20
            
            # Penalty por ser cliente directo si hay otras opciones
            if ip == client_ip and len(unique_ips) > 1:
                score -= 10
            
            ip_scores[ip] = score
        
        # Ordenar por score
        sorted_ips = sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)
        
        # Determinar real_ip y vpn_ip
        real_ip = sorted_ips[0][0]
        vpn_ip = None
        
        # Buscar la IP con score más bajo como posible VPN
        for ip, score in reversed(sorted_ips):
            if score < 0 and ip != real_ip:
                vpn_ip = ip
                break
        
        return real_ip, vpn_ip
    
    @staticmethod
    def is_datacenter_ip(isp):
        datacenter_indicators = [
            'DATACENTER', 'HOSTING', 'CLOUD', 'SERVER', 'AMAZON',
            'GOOGLE CLOUD', 'MICROSOFT AZURE', 'DIGITAL OCEAN',
            'LINODE', 'VULTR', 'OVH', 'HETZNER', 'CONTABO',
            'HOSTINGER', 'GODADDY', 'AWS', 'GCP', 'AZURE'
        ]
        return any(indicator in isp for indicator in datacenter_indicators)
    
    @staticmethod
    def is_residential_ip(isp):
        residential_indicators = [
            'TELECOM', 'CABLE', 'BROADBAND', 'INTERNET', 'COMMUNICATIONS',
            'COMCAST', 'VERIZON', 'AT&T', 'CHARTER', 'COX', 'TELMEX',
            'TELEFONICA', 'MOVISTAR', 'TOTALPLAY', 'MEGACABLE',
            'RESIDENTIAL', 'HOME', 'FIBER', 'DSL'
        ]
        return any(indicator in isp for indicator in residential_indicators)
    
    @staticmethod
    def is_mobile_ip(isp):
        mobile_indicators = [
            'MOBILE', 'CELLULAR', 'WIRELESS', 'T-MOBILE', 'SPRINT',
            'VODAFONE', 'ORANGE', 'TELEFONICA', 'TELCEL', 'ATT',
            '4G', '5G', 'LTE'
        ]
        return any(indicator in isp for indicator in mobile_indicators)

geo_intel = GeoIntelligence()
threat_analyzer = ThreatAnalyzer()

# Rutas principales
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/embed')
def embed():
    return render_template('embed.html')

@app.route('/api/intelligence/collect', methods=['POST'])
def collect_intelligence():
    try:
        data = request.json
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        print(f" Collecting intelligence from session: {data.get('sessionId', 'unknown')}")
        
        # Extraer IPs del payload
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
        
        public_ip = data.get('publicIP')
        
        # WebRTC candidates
        candidates = data.get('candidates', [])
        webrtc_ips = [c.get('ip') for c in candidates if c.get('ip')]
        
        # STUN discovered IPs
        stun_ips = data.get('stunDiscoveredIPs', [])
        
        # Crear mapa de datos geográficos
        all_unique_ips = list(set(filter(None, [client_ip, public_ip] + webrtc_ips + stun_ips)))
        geo_data_map = {}
        
        print(f" Analyzing {len(all_unique_ips)} unique IPs...")
        for ip in all_unique_ips:
            geo_data_map[ip] = geo_intel.analyze_ip(ip)
            print(f"    {ip}: {geo_data_map[ip]['city']}, {geo_data_map[ip]['country']} ({geo_data_map[ip]['isp']})")
        
        # Determinar IP real vs VPN
        real_ip, vpn_ip = threat_analyzer.determine_real_vs_vpn_ip(
            client_ip, webrtc_ips, stun_ips, public_ip, geo_data_map
        )
        
        print(f" Determined - Real IP: {real_ip}, VPN IP: {vpn_ip}")
        
        # Usar datos geo de la IP real
        geo_data = geo_data_map.get(real_ip, geo_data_map.get(client_ip, {}))
        
        # Análisis de amenazas mejorado
        fingerprint_data = data.get('fingerprint', {})
        timing_data = data.get('timingAnalysis', [])
        
        threat_level, is_corporate, vpn_detected, vm_detected, vpn_suspicion = threat_analyzer.analyze_threat_level(
            real_ip, data.get('userAgent', ''), geo_data.get('asn', ''), 
            fingerprint_data, timing_data
        )
        
        # Extraer información de VM
        vm_info = fingerprint_data.get('virtualization', {})
        
        # Guardar en base de datos
        intel_record = IPIntelligence(
            session_id=data.get('sessionId', 'unknown'),
            real_ip=real_ip,
            vpn_ip=vpn_ip,
            client_ip=client_ip,
            public_ip=public_ip,
            stun_ips=json.dumps(stun_ips),
            country=geo_data.get('country', 'Unknown'),
            city=geo_data.get('city', 'Unknown'),
            isp=geo_data.get('isp', 'Unknown'),
            asn=str(geo_data.get('asn', '')),
            user_agent=data.get('userAgent', ''),
            ice_candidates=json.dumps(candidates),
            fingerprint_hash=hashlib.md5(str(fingerprint_data).encode()).hexdigest(),
            threat_level=threat_level,
            is_corporate=is_corporate,
            vpn_detected=vpn_detected,
            vm_detected=vm_detected,
            vm_type=vm_info.get('vmType', ''),
            vm_confidence=vm_info.get('confidence', 0),
            timing_analysis=json.dumps(timing_data),
            vpn_suspicion=vpn_suspicion
        )
        
        db.session.add(intel_record)
        db.session.commit()
        
        # Status message mejorado
        status_parts = [f"REAL IP: {real_ip}"]
        if vm_detected:
            status_parts.append(f"VM: {vm_info.get('vmType', 'Unknown')}")
        if vpn_detected:
            status_parts.append(f"VPN: {vpn_ip}")
        elif vpn_suspicion:
            status_parts.append("VPN SUSPECTED")
        
        status_msg = " | ".join(status_parts)
        status_msg += f" | {geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}"
        
        print(f" {status_msg}")
        
        return jsonify({
            'status': 'success', 
            'id': intel_record.id,
            'analysis': {
                'real_ip': real_ip,
                'vpn_ip': vpn_ip,
                'vm_detected': vm_detected,
                'vpn_detected': vpn_detected,
                'threat_level': threat_level
            }
        })
        
    except Exception as e:
        print(f"Error collecting intelligence: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/intelligence')
def get_intelligence():
    try:
        records = IPIntelligence.query.order_by(IPIntelligence.created_at.desc()).limit(100).all()
        
        data = []
        for record in records:
            # Determinar el tipo de conexión
            connection_type = 'Home User'
            if record.vm_detected:
                connection_type = f' VM ({record.vm_type})' if record.vm_type else '🖥️ Virtual Machine'
            elif record.is_corporate:
                connection_type = 'Corporate'
            elif record.vpn_detected:
                connection_type = 'VPN User'
            elif record.vpn_suspicion:
                connection_type = 'VPN Suspected'
            
            data.append({
                'id': record.id,
                'real_ip': record.real_ip,
                'vpn_ip': record.vpn_ip,
                'client_ip': record.client_ip,
                'public_ip': record.public_ip,
                'country': record.country,
                'city': record.city,
                'isp': record.isp,
                'asn': record.asn,
                'threat_level': record.threat_level,
                'is_corporate': record.is_corporate,
                'vpn_detected': record.vpn_detected,
                'vm_detected': record.vm_detected,
                'vm_type': record.vm_type,
                'vm_confidence': record.vm_confidence,
                'vpn_suspicion': record.vpn_suspicion,
                'connection_type': connection_type,
                'created_at': record.created_at.isoformat()
            })
        
        return jsonify(data)
        
    except Exception as e:
        print(f"❌ Error getting intelligence: {str(e)}")
        return jsonify([])

@app.route('/api/stats')
def get_stats():
    try:
        total = IPIntelligence.query.count()
        vpn_bypassed = IPIntelligence.query.filter(
            (IPIntelligence.vpn_detected == True) | 
            (IPIntelligence.vpn_suspicion == True)
        ).count()
        corporate = IPIntelligence.query.filter(IPIntelligence.is_corporate == True).count()
        vm_detected = IPIntelligence.query.filter(IPIntelligence.vm_detected == True).count()
        countries = db.session.query(IPIntelligence.country).distinct().count()
        
        return jsonify({
            'total': total,
            'vpn_bypassed': vpn_bypassed,
            'corporate': corporate,
            'vm_detected': vm_detected,
            'countries': countries
        })
        
    except Exception as e:
        print(f"❌ Error getting stats: {str(e)}")
        return jsonify({
            'total': 0,
            'vpn_bypassed': 0,
            'corporate': 0,
            'vm_detected': 0,
            'countries': 0
        })

if __name__ == '__main__':
    print("WebRTC Intelligence Platform Enhanced")
    print("=" * 60)
    
    # Inicializar base de datos
    initialize_database()
    
    print("Starting enhanced server...")
    print(f"Dashboard: http://localhost:5000/dashboard")
    print(f"Demo page: http://localhost:5000")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
