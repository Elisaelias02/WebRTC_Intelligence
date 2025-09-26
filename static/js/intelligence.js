/**
 * WebRTC Intelligence Platform
 * Advanced IP Extraction and Analysis System
 */

class WebRTCIntelligencePlatform {
    constructor() {
        this.sessionId = this.generateSessionId();
        this.candidates = [];
        this.capabilities = {};
        this.startTime = performance.now();
        
        console.log('🕵️ WebRTC Intelligence Platform - Initializing...');
        this.initialize();
    }

    generateSessionId() {
        return 'sess_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
    }

    async initialize() {
        try {
            // Detect WebRTC capabilities
            await this.detectCapabilities();
            
            // Start IP extraction
            await this.extractIPIntelligence();
            
            // Generate browser fingerprint
            this.generateFingerprint();
            
        } catch (error) {
            console.error('Intelligence gathering failed:', error);
        }
    }

    async detectCapabilities() {
        this.capabilities = {
            webrtc: !!window.RTCPeerConnection,
            dataChannel: true,
            getUserMedia: !!navigator.mediaDevices?.getUserMedia,
            timestamp: new Date().toISOString()
        };
    }

    async extractIPIntelligence() {
        return new Promise((resolve) => {
            const pc = new RTCPeerConnection({
                iceServers: [
                    { urls: 'stun:stun.l.google.com:19302' },
                    { urls: 'stun:stun1.l.google.com:19302' },
                    { urls: 'stun:stun2.l.google.com:19302' },
                    { urls: 'stun:global.stun.twilio.com:3478' },
                    { urls: 'stun:stun.relay.metered.ca:80' }
                ]
            });

            let candidatesReceived = 0;
            const maxCandidates = 10;
            let timeout;

            pc.onicecandidate = (event) => {
                if (!event.candidate) {
                    this.sendIntelligenceData();
                    resolve(this.candidates);
                    return;
                }

                const candidate = event.candidate.candidate;
                const parsed = this.parseICECandidate(candidate);
                
                if (parsed && this.isValidIP(parsed.ip)) {
                    candidatesReceived++;
                    
                    const candidateData = {
                        ip: parsed.ip,
                        port: parsed.port,
                        type: parsed.type,
                        protocol: parsed.protocol,
                        foundation: parsed.foundation,
                        priority: parsed.priority,
                        discoveryTime: performance.now() - this.startTime,
                        timestamp: new Date().toISOString()
                    };
                    
                    this.candidates.push(candidateData);
                    
                    console.log(`🎯 IP Candidate found: ${parsed.ip} (${parsed.type})`);
                    
                    // Stop after collecting enough candidates or timeout
                    if (candidatesReceived >= maxCandidates) {
                        pc.close();
                        clearTimeout(timeout);
                        this.sendIntelligenceData();
                        resolve(this.candidates);
                    }
                }
            };

            pc.onicecandidateerror = (event) => {
                console.warn('ICE candidate error:', event);
            };

            // Create data channel to trigger candidate gathering
            const dataChannel = pc.createDataChannel('intelligence', {
                ordered: false,
                maxRetransmits: 0
            });

            dataChannel.onopen = () => {
                console.log('📡 Data channel opened');
            };

            // Create offer to start ICE gathering
            pc.createOffer()
                .then(offer => pc.setLocalDescription(offer))
                .catch(error => {
                    console.error('Failed to create offer:', error);
                    resolve([]);
                });

            // Timeout after 8 seconds
            timeout = setTimeout(() => {
                console.log('⏰ Intelligence gathering timeout');
                pc.close();
                this.sendIntelligenceData();
                resolve(this.candidates);
            }, 8000);
        });
    }

    parseICECandidate(candidateString) {
        try {
            const parts = candidateString.split(' ');
            if (parts.length < 8) return null;

            return {
                foundation: parts[0],
                component: parseInt(parts[1]),
                protocol: parts[2],
                priority: parseInt(parts[3]),
                ip: parts[4],
                port: parseInt(parts[5]),
                type: parts[7],
                relAddr: parts[9] || null,
                relPort: parts[11] ? parseInt(parts[11]) : null
            };
        } catch (error) {
            console.error('Failed to parse candidate:', error);
            return null;
        }
    }

    isValidIP(ip) {
        if (!ip) return false;
        
        // Skip localhost, broadcast, and invalid IPs
        const skipPatterns = [
            /^127\./,           // localhost
            /^0\./,             // invalid
            /^169\.254\./,      // link-local
            /^224\./,           // multicast
            /^255\./            // broadcast
        ];
        
        return !skipPatterns.some(pattern => pattern.test(ip)) && 
               /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip);
    }

    generateFingerprint() {
        const fingerprint = {
            userAgent: navigator.userAgent,
            language: navigator.language,
            languages: navigator.languages,
            platform: navigator.platform,
            cookieEnabled: navigator.cookieEnabled,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            screen: {
                width: screen.width,
                height: screen.height,
                colorDepth: screen.colorDepth,
                pixelDepth: screen.pixelDepth
            },
            viewport: {
                width: window.innerWidth,
                height: window.innerHeight
            },
            webgl: this.getWebGLInfo(),
            canvas: this.getCanvasFingerprint()
        };

        this.fingerprint = fingerprint;
        return fingerprint;
    }

    getWebGLInfo() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            
            if (!gl) return null;

            return {
                vendor: gl.getParameter(gl.VENDOR),
                renderer: gl.getParameter(gl.RENDERER),
                version: gl.getParameter(gl.VERSION),
                shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION)
            };
        } catch (error) {
            return null;
        }
    }

    getCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('WebRTC Intelligence 🕵️', 2, 2);
            
            return canvas.toDataURL().slice(-50); // Last 50 chars as fingerprint
        } catch (error) {
            return null;
        }
    }

    async getPublicIP() {
        try {
            const response = await fetch('https://api.ipify.org?format=json');
            const data = await response.json();
            return data.ip;
        } catch (error) {
            return null;
        }
    }

    async sendIntelligenceData() {
        try {
            const publicIP = await this.getPublicIP();
            
            const payload = {
                sessionId: this.sessionId,
                candidates: this.candidates,
                capabilities: this.capabilities,
                fingerprint: this.fingerprint,
                publicIP: publicIP,
                userAgent: navigator.userAgent,
                language: navigator.language,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                referrer: document.referrer,
                url: window.location.href,
                timestamp: new Date().toISOString(),
                totalTime: performance.now() - this.startTime
            };

            const response = await fetch('/api/intelligence/collect', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                const result = await response.json();
                console.log('✅ Intelligence data transmitted successfully:', result);
            } else {
                console.error('❌ Failed to transmit intelligence data');
            }

        } catch (error) {
            console.error('❌ Intelligence transmission error:', error);
        }
    }

    // Advanced network topology discovery
    async discoverNetworkTopology() {
        const localRanges = [
            '192.168.1',
            '192.168.0', 
            '10.0.0',
            '172.16.0'
        ];

        // This would be used for advanced scanning (demo purposes only)
        console.log('🌐 Network topology discovery initiated');
    }
}

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new WebRTCIntelligencePlatform();
    });
} else {
    new WebRTCIntelligencePlatform();
}

// Expose for debugging
window.WebRTCIntelligence = WebRTCIntelligencePlatform;
