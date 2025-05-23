// --- Global State ---
let connectionState = 'CLOSED';
let clientSequenceNum = Math.floor(Math.random() * 100000); // Initial Client Seq
let clientAckNum = 0;
let serverSequenceNum = 0; // Initial Server Seq (will be set during SYN-ACK)
let serverAckNum = 0;

let congestionWindow = 1; // In MSS (Maximum Segment Size)
let ssthresh = 64; // In MSS
let mss = 1460; // bytes (typical Ethernet, IP+TCP header = 40, so 1500-40)

let simulatedRTT = 50; // milliseconds
let packetsSentCount = 0;
let packetsReceivedCount = 0;
let dataPacketsLostCount = 0;
let retransmissionsCount = 0;
let appDataSentBytes = 0;
let totalOverheadBytes = 0;

let isPacketLossActive = false;
let currentPacketId = 0; // For identifying packets if loss occurs

const SIM_DELAY_SHORT = 300;
const SIM_DELAY_MEDIUM = 500;
const SIM_DELAY_LONG = 1000;

// --- Network Addresses (Constants) ---
const srcIP = '192.168.1.100';
const destIP = '203.0.113.50';
const srcMAC = '00:1A:2B:3C:4D:5E';
const destMAC = '00:AA:BB:CC:DD:EE';
const srcPort = 12345;
const destPort = 80; // HTTP
const ETHERTYPE_IPV4 = '0800';
const IP_PROTOCOL_TCP = '06';

// --- Utility Functions ---
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function log(message, layer = 'sys', packetInfo = '') {
    const logDiv = document.getElementById('sequenceLog');
    const entry = document.createElement('div');
    entry.className = `log-entry log-${layer.toLowerCase()}`;
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 });
    entry.innerHTML = `<span class="timestamp">${time}</span> [${layer.toUpperCase()}] ${message} ${packetInfo ? `<span style="color:#88aaff;">${packetInfo}</span>` : ''}`;
    logDiv.appendChild(entry);
    logDiv.scrollTop = logDiv.scrollHeight;
}

function updateStatus(elementId, statusText) {
    document.getElementById(elementId).textContent = statusText;
}

function highlightLayer(layerId, duration = SIM_DELAY_MEDIUM * 1.5, isError = false) {
    const layer = document.getElementById(layerId);
    if (!layer) return;
    layer.classList.add('active');
    if (isError) layer.classList.add('error-highlight');
    
    return new Promise(resolve => {
        setTimeout(() => {
            layer.classList.remove('active');
            if (isError) layer.classList.remove('error-highlight');
            resolve();
        }, duration);
    });
}

function stringToHex(str) {
    return Array.from(str).map(c => 
        c.charCodeAt(0) < 128 ? c.charCodeAt(0).toString(16).padStart(2, '0') : encodeURIComponent(c).replace(/%/g,'').toLowerCase()
    ).join('');
}

function hexToString(hex) {
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
}

function hexToBinary(hexStr) {
    return hexStr.split('').map(hexDigit => 
        parseInt(hexDigit, 16).toString(2).padStart(4, '0')
    ).join('');
}

function binaryToHex(binStr) {
    if (binStr.length % 4 !== 0) {
         // Pad if not multiple of 4, though ideally it should be
        binStr = binStr.padStart(Math.ceil(binStr.length / 4) * 4, '0');
    }
    let hex = "";
    for (let i = 0; i < binStr.length; i += 4) {
        const chunk = binStr.substring(i, i + 4);
        hex += parseInt(chunk, 2).toString(16);
    }
    return hex;
}

function formatHexDisplay(hexStr, bytesPerLine = 16) {
    let formatted = "";
    for (let i = 0; i < hexStr.length; i += 2) {
        formatted += hexStr.substring(i, i + 2) + " ";
        if ((i / 2 + 1) % bytesPerLine === 0) {
            formatted += "\n";
        }
    }
    return formatted.trim();
}

function formatBinaryDisplay(binStr, bitsPerLine = 64) {
    let formatted = "";
    for (let i = 0; i < binStr.length; i++) {
        formatted += binStr[i];
        if ((i + 1) % 8 === 0) formatted += " "; // Space after each byte
        if ((i + 1) % bitsPerLine === 0) formatted += "\n";
    }
    return formatted.trim().substring(0, 512) + (binStr.length > 512 ? "..." : ""); // Truncate for display
}

function ipToHex(ipStr) {
    return ipStr.split('.').map(octet => parseInt(octet, 10).toString(16).padStart(2, '0')).join('');
}
function macToHex(macStr) {
    return macStr.split(':').map(part => part.toLowerCase()).join('');
}

// --- Header Creation ---
function createTCPHeader(appDataLength, flags = { SYN:0, ACK:0, PSH:0, FIN:0 }) {
    const srcPortHex = srcPort.toString(16).padStart(4, '0');
    const destPortHex = destPort.toString(16).padStart(4, '0');
    const seqHex = clientSequenceNum.toString(16).padStart(8, '0');
    const ackHex = clientAckNum.toString(16).padStart(8, '0');
    
    const dataOffset = '5'; // 5 x 4 bytes = 20 bytes header (no options)
    const reserved = '0';   // 3 bits reserved + NS flag (1 bit) = 0 for now
    let flagsHex = 0;
    if (flags.FIN) flagsHex |= 1;
    if (flags.SYN) flagsHex |= 2;
    // RST flag would be 4
    if (flags.PSH) flagsHex |= 8;
    if (flags.ACK) flagsHex |= 16;
    // URG flag would be 32
    const headerLengthAndFlags = dataOffset + reserved + flagsHex.toString(16).padStart(1, '0'); // e.g., 5018 for PSH,ACK (5 for offset, 0 for res, 18 for flags)
                                                                                            // More correctly: dataOffset (4bits), reserved (4bits=0), flags (8bits)
                                                                                            // So, ( (5 << 4) | 0 ).toString(16) + flagsHex.toString(16).padStart(2,'0') = 50 + flagsHex
    const dataOffsetAndFlags = (5 << 12) | // Data offset (5 * 32-bit words)
                           (flags.SYN << 1) | (flags.ACK << 4) | (flags.PSH << 3) | (flags.FIN); // simplified flags for now

    const flagsByteVal = (flags.FIN ? 1:0) + (flags.SYN ? 2:0) + (flags.PSH ? 8:0) + (flags.ACK ? 16:0);


    const windowSize = (congestionWindow * mss).toString(16).padStart(4, '0'); // Window size from CWND
    const checksum = '0000'; // Placeholder
    const urgentPointer = '0000';
    
    //TCP Pseudo Header for checksum: SrcIP, DestIP, 00, Protocol (6), TCP length
    const pseudoSrcIp = ipToHex(srcIP);
    const pseudoDestIp = ipToHex(destIP);
    const pseudoProtocol = '00' + IP_PROTOCOL_TCP;
    const tcpLength = (20 + appDataLength).toString(16).padStart(4,'0');
    
    const pseudoHeader = pseudoSrcIp + pseudoDestIp + pseudoProtocol + tcpLength;
    const partialTcpHeader = srcPortHex + destPortHex + seqHex + ackHex + 
                        '50' + // Data Offset (5*4=20 bytes), Reserved (0), NS (0)
                        flagsByteVal.toString(16).padStart(2, '0') + // Flags
                        windowSize + 
                        checksum + // Temp checksum
                        urgentPointer;

    const calculatedChecksum = calculateTCPChecksum(pseudoHeader, partialTcpHeader, stringToHex(appDataLength > 0 ? document.getElementById('originalData').textContent.substring(0, appDataLength) : ""));
    document.getElementById('tcpChecksumStatus').textContent = `TCP Checksum: 0x${calculatedChecksum} (Calculated)`;


    return srcPortHex + destPortHex + seqHex + ackHex + 
           '50' + // Data Offset (5*4=20 bytes), Reserved (0), NS (0)
           flagsByteVal.toString(16).padStart(2, '0') + // Flags
           windowSize + 
           calculatedChecksum + // Real checksum
           urgentPointer;
}

function createIPHeader(tcpSegmentLength) {
    const versionIHL = '45'; // IPv4, IHL 5 (20 bytes)
    const dscpECN = '00';    // Differentiated Services / ECN
    const totalLength = (20 + tcpSegmentLength).toString(16).padStart(4, '0'); // IP Header + TCP Segment
    const identification = (packetsSentCount + 1).toString(16).padStart(4, '0'); // Simple ID
    const flagsFragmentOffset = '4000'; // Flags: Don't Fragment set, Fragment Offset: 0
    const ttl = '40'; // TTL 64 (decimal)
    const protocol = IP_PROTOCOL_TCP; // TCP
    const headerChecksum = '0000'; // Placeholder before calculation
    const sourceIPHex = ipToHex(srcIP);
    const destIPHex = ipToHex(destIP);

    const partialIpHeader = versionIHL + dscpECN + totalLength + identification +
                         flagsFragmentOffset + ttl + protocol + headerChecksum +
                         sourceIPHex + destIPHex;
    const calculatedChecksum = calculateIPChecksum(partialIpHeader.replace(headerChecksum, "0000")); // Calculate with checksum field as 0
    document.getElementById('ipChecksumStatus').textContent = `IP Checksum: 0x${calculatedChecksum} (Calculated)`;
    
    return versionIHL + dscpECN + totalLength + identification +
           flagsFragmentOffset + ttl + protocol + calculatedChecksum +
           sourceIPHex + destIPHex;
}

function createEthernetHeader() {
    const destMACHex = macToHex(destMAC);
    const srcMACHex = macToHex(srcMAC);
    const etherType = ETHERTYPE_IPV4; // IPv4
    return destMACHex + srcMACHex + etherType;
}

function createEthernetTrailer(frameDataWithoutFCSHex) {
    // FCS is typically a 4-byte CRC. We'll use a placeholder.
    const fcs = "12345678"; // Placeholder FCS
    document.getElementById('ethChecksumStatus').textContent = `Ethernet FCS: 0x${fcs} (Placeholder)`;
    return fcs;
}

// --- Header Parsing and Display ---
function parseHTTPHeaders(httpData) {
    const headers = {};
    const lines = httpData.split('\r\n');
    if (lines.length > 0) headers['Request Line'] = lines[0];
    for (let i = 1; i < lines.length; i++) {
        if (lines[i] === '') break; // End of headers
        const [name, ...valueParts] = lines[i].split(':');
        if (name && valueParts.length > 0) {
            headers[name.trim()] = valueParts.join(':').trim();
        }
    }
    return headers;
}

function parseTCPHeader(tcpHeaderHex) {
    return {
        'Source Port': parseInt(tcpHeaderHex.substring(0, 4), 16),
        'Dest Port': parseInt(tcpHeaderHex.substring(4, 8), 16),
        'Sequence Num': parseInt(tcpHeaderHex.substring(8, 16), 16),
        'Ack Num': parseInt(tcpHeaderHex.substring(16, 24), 16),
        'Data Offset': `${parseInt(tcpHeaderHex.substring(24, 25), 16) * 4} bytes`,
        'Flags': `0x${tcpHeaderHex.substring(25, 28)} (Binary: ${parseInt(tcpHeaderHex.substring(26,28),16).toString(2).padStart(8,'0')})`, // Simplified flags
        'Window Size': parseInt(tcpHeaderHex.substring(28, 32), 16),
        'Checksum': `0x${tcpHeaderHex.substring(32, 36)}`,
        'Urgent Pointer': parseInt(tcpHeaderHex.substring(36, 40), 16)
    };
}

function parseIPHeader(ipHeaderHex) {
    const version = parseInt(ipHeaderHex.substring(0, 1), 16);
    const ihl = parseInt(ipHeaderHex.substring(1, 2), 16) * 4;
    return {
        'Version': version,
        'IHL': `${ihl} bytes`,
        'DSCP/ECN': `0x${ipHeaderHex.substring(2, 4)}`,
        'Total Length': `${parseInt(ipHeaderHex.substring(4, 8), 16)} bytes`,
        'Identification': `0x${ipHeaderHex.substring(8, 12)}`,
        'Flags/Frag Offset': `0x${ipHeaderHex.substring(12, 16)}`,
        'TTL': parseInt(ipHeaderHex.substring(16, 18), 16),
        'Protocol': `0x${ipHeaderHex.substring(18, 20)} (${parseInt(ipHeaderHex.substring(18, 20),16) === 6 ? 'TCP' : 'Other'})`,
        'Header Checksum': `0x${ipHeaderHex.substring(20, 24)}`,
        'Source IP': hexToIp(ipHeaderHex.substring(24, 32)),
        'Dest IP': hexToIp(ipHeaderHex.substring(32, 40))
    };
}
function hexToIp(hex) {
    return [parseInt(hex.substring(0,2),16), parseInt(hex.substring(2,4),16), parseInt(hex.substring(4,6),16), parseInt(hex.substring(6,8),16)].join('.');
}


function parseEthernetHeader(ethHeaderHex) {
    return {
        'Dest MAC': hexToMac(ethHeaderHex.substring(0, 12)),
        'Source MAC': hexToMac(ethHeaderHex.substring(12, 24)),
        'EtherType': `0x${ethHeaderHex.substring(24, 28)} (${ethHeaderHex.substring(24,28) === ETHERTYPE_IPV4 ? 'IPv4' : 'Other'})`
    };
}
function hexToMac(hex) {
    return hex.match(/.{1,2}/g).join(':').toUpperCase();
}

function displayHeaders(elementId, headersObject) {
    const container = document.getElementById(elementId);
    container.innerHTML = ''; // Clear previous
    for (const [name, value] of Object.entries(headersObject)) {
        const fieldDiv = document.createElement('div');
        fieldDiv.className = 'header-field';
        fieldDiv.innerHTML = `<span class="field-name">${name}</span><span class="field-value">${value}</span>`;
        container.appendChild(fieldDiv);
    }
}

// --- Checksum Calculations (Simplified) ---
function calculateIPChecksum(ipHeaderHexNoChecksum) {
    let sum = 0;
    // IP header is always 20 bytes for this sim (IHL=5)
    for (let i = 0; i < ipHeaderHexNoChecksum.length; i += 4) { // Iterate over 16-bit words (4 hex chars)
        // Ensure we don't try to read past the checksum field if it was already included as 0000
        if (i === 20 && ipHeaderHexNoChecksum.substring(i, i+4) === "0000") { // Checksum field index for 20-byte header
             sum += 0; // Add the placeholder zero
             continue;
        }
        const word = parseInt(ipHeaderHexNoChecksum.substring(i, i + 4), 16);
        sum += word;
    }
    while (sum >> 16) { // Carry
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ( (~sum) & 0xFFFF ).toString(16).padStart(4, '0');
}

function calculateTCPChecksum(pseudoHeaderHex, tcpHeaderHexNoChecksumAndData, appDataHex) {
    // Simplified: For actual TCP checksum, you'd sum pseudo-header, TCP header (checksum field as 0), and TCP data
    // For this simulation, we'll do a very basic sum of parts as a placeholder
    let sum = 0;
    const combined = pseudoHeaderHex + tcpHeaderHexNoChecksumAndData.replace(tcpHeaderHexNoChecksumAndData.substring(32,36), "0000") + appDataHex; // Replace checksum field with 0000

    for (let i = 0; i < combined.length; i += 4) {
        const word = parseInt(combined.substring(i, i + 4) || "0", 16); // Ensure parsing valid hex
        sum += word;
    }
     // Add padding if odd number of data bytes
    if ((appDataHex.length / 2) % 2 !== 0) {
        sum += parseInt((appDataHex.slice(-2) + "00").substring(0,4), 16) ; // This logic might be off for true TCP padding
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ((~sum) & 0xFFFF).toString(16).padStart(4, '0');
}


// --- Manchester Encoding ---
function manchesterEncode(binaryString) {
    return binaryString.split('').map(bit => bit === '0' ? '01' : '10').join('');
}
function manchesterDecode(manchesterString) {
    let binary = '';
    for (let i = 0; i < manchesterString.length; i += 2) {
        const pair = manchesterString.substring(i, i + 2);
        if (pair === '01') binary += '0';
        else if (pair === '10') binary += '1';
        else { /* Error in encoding */ binary += '?'; } 
    }
    return binary;
}

// --- UI and State Updates ---
function updateTCPState() {
    document.getElementById('tcpStateDisplay').innerHTML = 
        `State: ${connectionState}<br>
         Client Seq: ${clientSequenceNum} | Client Ack: ${clientAckNum}<br>
         Server Seq: ${serverSequenceNum} | Server Ack: ${serverAckNum}<br>
         CWND: ${congestionWindow} MSS | SSThresh: ${ssthresh} MSS`;
    document.getElementById('senderCongestionWindow').textContent = `Congestion Window (CWND): ${congestionWindow} MSS | SSThresh: ${ssthresh} MSS`;
}

function updateNetworkStats() {
     document.getElementById('networkStats').innerHTML = 
        `Packets Sent: ${packetsSentCount}<br>
         Packets Received: ${packetsReceivedCount}<br>
         Data Packets Lost: ${dataPacketsLostCount}<br>
         Retransmissions: ${retransmissionsCount}<br>
         Simulated RTT: ${simulatedRTT}ms`;
}
function updateProtocolAnalysis() {
    const efficiency = appDataSentBytes > 0 ? ((appDataSentBytes / (appDataSentBytes + totalOverheadBytes)) * 100).toFixed(2) : 0;
    // Simplified throughput based on last RTT and data amount
    const lastPacketDataBytes = document.getElementById('originalData').textContent.length; // Approximation
    const throughputBps = packetsSentCount > 0 ? ((lastPacketDataBytes * 8) / (simulatedRTT / 1000)).toFixed(0) : 0;

    document.getElementById('protocolAnalysis').innerHTML = 
        `Total Data Sent (App): ${appDataSentBytes} bytes<br>
         Total Overhead: ${totalOverheadBytes} bytes<br>
         Efficiency: ${efficiency}%<br>
         Est. Throughput: ${throughputBps} bps`;
}

// --- Main Simulation Functions ---
async function initializeConnection() {
    log('Initializing TCP connection...', 'tcp');
    updateStatus('connectionStatus', 'Connection Status: Establishing...');
    document.getElementById('initBtn').disabled = true;
    document.getElementById('sendBtn').disabled = true;
    document.getElementById('lossBtn').disabled = true;
    document.getElementById('congBtn').disabled = true;

    connectionState = 'SYN_SENT';
    updateTCPState();
    updateStatus('tcpStatus', 'SYN_SENT');
    updateStatus('rxTcpStatus', 'LISTEN'); // Server implicitly listens

    // 1. Client sends SYN
    let synHeader = createTCPHeader(0, { SYN: 1 });
    log(`Client -> Server: SYN`, 'tcp', `Seq=${clientSequenceNum}, Win=${congestionWindow*mss}`);
    highlightLayer('senderTCP');
    // (Full stack processing for SYN would happen here in a more detailed sim)
    await sleep(SIM_DELAY_MEDIUM);
    highlightLayer('receiverPhy', SIM_DELAY_SHORT); // Simulate reception
    
    // 2. Server receives SYN, sends SYN-ACK
    serverSequenceNum = Math.floor(Math.random() * 100000); // Server's ISN
    serverAckNum = clientSequenceNum + 1; // Ack client's SYN
    clientSequenceNum++; // SYN consumes one sequence number
    
    connectionState = 'SYN_RCVD'; // From server's perspective
    log(`Server -> Client: SYN-ACK`, 'tcp', `Seq=${serverSequenceNum}, Ack=${serverAckNum}, Win=65535`); // Server uses its own window
    highlightLayer('receiverTCP');
    updateStatus('rxTcpStatus', 'SYN_RCVD');
    await sleep(SIM_DELAY_MEDIUM);
    highlightLayer('senderPhy', SIM_DELAY_SHORT); // Simulate reception

    // 3. Client receives SYN-ACK, sends ACK
    clientAckNum = serverSequenceNum + 1; // Ack server's SYN
    serverSequenceNum++; // Server's SYN also consumes one sequence number
    
    connectionState = 'ESTABLISHED';
    updateTCPState();
    updateStatus('tcpStatus', 'ESTABLISHED');
    updateStatus('rxTcpStatus', 'ESTABLISHED'); // Also established on server
    updateStatus('connectionStatus', 'Connection Status: ESTABLISHED');
    
    let ackHeader = createTCPHeader(0, { ACK: 1 });
    log(`Client -> Server: ACK`, 'tcp', `Seq=${clientSequenceNum}, Ack=${clientAckNum}`);
    highlightLayer('senderTCP');
    await sleep(SIM_DELAY_MEDIUM);
    highlightLayer('receiverPhy', SIM_DELAY_SHORT);


    document.getElementById('sendBtn').disabled = false;
    document.getElementById('lossBtn').disabled = false;
    document.getElementById('congBtn').disabled = false;
    log('TCP connection established successfully.', 'sys');
}

async function sendData() {
    if (connectionState !== 'ESTABLISHED') {
        log('Cannot send data: Connection not established.', 'error', true);
        return;
    }
    document.getElementById('sendBtn').disabled = true; // Prevent rapid clicks
    currentPacketId++;
    log(`--- Sending Data Packet ID: ${currentPacketId} ---`, 'sys');
    
    const originalHttpData = document.getElementById('originalData').textContent;
    const appDataLength = originalHttpData.length;
    appDataSentBytes += appDataLength;
    totalOverheadBytes = 0; // Reset for this packet

    // SENDER STACK
    await processApplicationLayer(originalHttpData);
    const tcpSegmentHex = await processTransportLayer(appDataLength); // Contains TCP header + app data hex
    const ipPacketHex = await processNetworkLayer(tcpSegmentHex.length / 2); // Pass TCP segment length
    const ethFrameHex = await processDataLinkLayer(ipPacketHex.length / 2); // Pass IP packet length
    const physicalLayerBits = await processPhysicalLayer(ethFrameHex);

    await simulateTransmission();

    if (isPacketLossActive && Math.random() < 0.3) { // 30% chance of loss if active
        log(`Packet ID ${currentPacketId} LOST in transit!`, 'error', true);
        dataPacketsLostCount++;
        updateNetworkStats();
        // In a real scenario, sender would timeout and retransmit. Here, we just log.
        // For simplicity, we don't proceed to receiver stack.
        document.getElementById('sendBtn').disabled = false;
        retransmissionsCount++; // Assuming a retransmission would occur
        // Reduce congestion window on loss (simplified TCP behavior)
        ssthresh = Math.max(2, Math.floor(congestionWindow / 2));
        congestionWindow = 1; // Go back to slow start
        updateTCPState();
        return;
    }
    
    // RECEIVER STACK
    await processReceiveStack(physicalLayerBits, ethFrameHex, ipPacketHex, tcpSegmentHex, originalHttpData);
    
    // TCP ACK from Receiver (Simplified: Assume receiver ACKs data immediately)
    // Server acks the data received. clientAckNum becomes server's new Seq.
    // clientSequenceNum remains same, serverAckNum gets updated to clientSequenceNum + dataLength
    serverAckNum = clientSequenceNum + appDataLength; 
    log(`Server -> Client: ACK (for data)`, 'tcp', `Seq=${serverSequenceNum}, Ack=${serverAckNum}`);
    // (client would process this ACK and potentially slide its window)
    await sleep(SIM_DELAY_SHORT);

    // Client updates its sequence number for next send
    clientSequenceNum += appDataLength;

    packetsSentCount++;
    updateNetworkStats();
    updateProtocolAnalysis();
    updateTCPState(); // Update with new seq/ack numbers
    document.getElementById('sendBtn').disabled = false;
}

async function processApplicationLayer(httpData) {
    await highlightLayer('senderApp');
    updateStatus('appStatus', 'Processing');
    displayHeaders('httpHeaders', parseHTTPHeaders(httpData));
    log(`App: HTTP Request prepared`, 'app', `(${httpData.length} bytes)`);
    await sleep(SIM_DELAY_SHORT);
    updateStatus('appStatus', 'Complete');
}

async function processTransportLayer(appDataLen) {
    await highlightLayer('senderTCP');
    updateStatus('tcpStatus', 'Segmenting');
    const tcpHeader = createTCPHeader(appDataLen, { ACK: 1, PSH: 1 });
    const appDataHex = stringToHex(document.getElementById('originalData').textContent.substring(0, appDataLen)); // Ensure correct data
    const tcpSegmentHex = tcpHeader + appDataHex;
    document.getElementById('tcpFrame').textContent = formatHexDisplay(tcpSegmentHex);
    displayHeaders('tcpHeaders', parseTCPHeader(tcpHeader));
    updateCongestionWindowBehavior(); // Update CWND based on ACK reception (simplified here before sending)
    updateTCPState();
    log(`TCP: Segment created`, 'tcp', `Seq=${clientSequenceNum}, Len=${appDataLen}, Flags=PSH,ACK`);
    totalOverheadBytes += tcpHeader.length / 2;
    await sleep(SIM_DELAY_MEDIUM);
    updateStatus('tcpStatus', 'Ready');
    return tcpSegmentHex;
}

function updateCongestionWindowBehavior() {
    // Simplified: AIMD for ESTABLISHED, Slow Start otherwise (though handshake sets to established)
    if (congestionWindow < ssthresh) {
        congestionWindow *= 2; // Slow start
        log("CWND: Slow Start, doubled to " + congestionWindow + " MSS", "tcp");
    } else {
        congestionWindow += 1; // Congestion avoidance
        log("CWND: Congestion Avoidance, incremented to " + congestionWindow + " MSS", "tcp");
    }
}


async function processNetworkLayer(tcpSegmentLen) {
    await highlightLayer('senderIP');
    updateStatus('ipStatus', 'Routing');
    const ipHeader = createIPHeader(tcpSegmentLen);
    const tcpSegmentFromUI = document.getElementById('tcpFrame').textContent.replace(/\s/g, ''); // Get from UI
    const ipPacketHex = ipHeader + tcpSegmentFromUI;
    document.getElementById('ipPacket').textContent = formatHexDisplay(ipPacketHex);
    displayHeaders('ipHeaders', parseIPHeader(ipHeader));
    log(`IP: Packet created`, 'ip', `${srcIP} → ${destIP}, TotalLen=${(ipHeader.length + tcpSegmentFromUI.length)/2}`);
    totalOverheadBytes += ipHeader.length / 2;
    await sleep(SIM_DELAY_MEDIUM);
    updateStatus('ipStatus', 'Complete');
    return ipPacketHex;
}

async function processDataLinkLayer(ipPacketLen) {
    await highlightLayer('senderEth');
    updateStatus('ethStatus', 'Framing');
    const ethHeader = createEthernetHeader();
    const ipPacketFromUI = document.getElementById('ipPacket').textContent.replace(/\s/g, '');
    const ethTrailer = createEthernetTrailer(ethHeader + ipPacketFromUI);
    const ethFrameHex = ethHeader + ipPacketFromUI + ethTrailer;
    document.getElementById('ethFrame').textContent = formatHexDisplay(ethFrameHex);
    displayHeaders('ethHeaders', parseEthernetHeader(ethHeader));
    log(`Eth: Frame created`, 'eth', `${srcMAC} → ${destMAC}`);
    totalOverheadBytes += (ethHeader.length + ethTrailer.length) / 2;
    await sleep(SIM_DELAY_MEDIUM);
    updateStatus('ethStatus', 'Complete');
    return ethFrameHex;
}

async function processPhysicalLayer(ethFrameHex) {
    await highlightLayer('senderPhy');
    updateStatus('phyStatus', 'Transmitting');
    const binaryBits = hexToBinary(ethFrameHex);
    const manchesterEncoded = manchesterEncode(binaryBits);
    document.getElementById('physicalBits').textContent = formatBinaryDisplay(manchesterEncoded);
    log(`Phy: Transmitting ${binaryBits.length} bits (Manchester: ${manchesterEncoded.length})`, 'phy');
    await sleep(SIM_DELAY_MEDIUM);
    updateStatus('phyStatus', 'Idle');
    return manchesterEncoded;
}

async function simulateTransmission() {
    log('Network: Packet traveling through infrastructure...', 'sys');
    const packetViz = document.getElementById('movingPacket');
    packetViz.style.left = '10px'; // Ensure it's at start
    packetViz.style.display = 'flex';
    
    // Force reflow to apply start position before transition
    packetViz.getBoundingClientRect(); 
    
    packetViz.style.left = `calc(100% - 50px)`; // End position
    
    // Adjust sleep to match transition + a little buffer
    await sleep(1800 + SIM_DELAY_SHORT); 
    packetViz.style.display = 'none';
}

async function processReceiveStack(receivedManchester, ethFrameHex, ipPacketHex, tcpSegmentHex, originalHttpData) {
    log(`--- Receiving Packet ID: ${currentPacketId} ---`, 'sys');
    // Phy Layer
    await highlightLayer('receiverPhy');
    updateStatus('rxPhyStatus', 'Receiving');
    document.getElementById('rxPhysicalBits').textContent = formatBinaryDisplay(receivedManchester);
    const decodedBinary = manchesterDecode(receivedManchester);
    const receivedFrameHexFromBinary = binaryToHex(decodedBinary);
    // Basic check: compare length. A real check would be more robust.
    if (receivedFrameHexFromBinary.substring(0, ethFrameHex.length) !== ethFrameHex) {
         log('Phy: Potential signal corruption! Decoded bits mismatch expected frame.', 'error', true);
         document.getElementById('rxPhyStatus').classList.add('error-highlight');
         // return; // Stop processing if critical error
    } else {
        log('Phy: Bits received, Manchester decoded.', 'phy');
    }
    updateStatus('rxPhyStatus', 'Sync Locked');
    await sleep(SIM_DELAY_MEDIUM);

    // Data Link Layer
    await highlightLayer('receiverEth');
    updateStatus('rxEthStatus', 'Processing');
    document.getElementById('rxEthFrame').textContent = formatHexDisplay(ethFrameHex); // Show expected frame for now
    const parsedEthHeader = parseEthernetHeader(ethFrameHex.substring(0, 28)); // 14 bytes header
    displayHeaders('rxEthHeaders', parsedEthHeader);
    // FCS Check (Placeholder)
    const receivedFCS = ethFrameHex.slice(-8);
    const expectedFCS = "12345678"; // from createEthernetTrailer
    const fcsOk = receivedFCS === expectedFCS;
    document.getElementById('rxEthChecksumStatus').textContent = `Ethernet FCS Check: ${fcsOk ? 'OK' : 'FAIL'} (0x${receivedFCS})`;
    if (!fcsOk) {
        log('Eth: FCS Mismatch! Frame potentially corrupted.', 'error', true);
        highlightLayer('receiverEth', SIM_DELAY_LONG, true);
        // return; // Stop processing
    } else {
        log('Eth: Frame validated (FCS OK), decapsulating IP packet.', 'eth');
    }
    updateStatus('rxEthStatus', 'Ready');
    await sleep(SIM_DELAY_MEDIUM);

    // Network Layer
    await highlightLayer('receiverIP');
    updateStatus('rxIpStatus', 'Processing');
    document.getElementById('rxIpPacket').textContent = formatHexDisplay(ipPacketHex); // Show expected
    const ipHeaderHexOnly = ipPacketHex.substring(0, 40); // 20 bytes header
    const parsedIpHeader = parseIPHeader(ipHeaderHexOnly);
    displayHeaders('rxIpHeaders', parsedIpHeader);
    // IP Checksum (Placeholder)
    const receivedIpChecksum = parsedIpHeader['Header Checksum'].substring(2);
    const calculatedIpChecksum = calculateIPChecksum(ipHeaderHexOnly.replace(receivedIpChecksum, "0000"));
    const ipChecksumOk = receivedIpChecksum.toLowerCase() === calculatedIpChecksum.toLowerCase();
    document.getElementById('rxIpChecksumStatus').textContent = `IP Checksum Check: ${ipChecksumOk ? 'OK' : 'FAIL'} (Rcv:0x${receivedIpChecksum}, Calc:0x${calculatedIpChecksum})`;
     if (!ipChecksumOk) {
        log('IP: Header Checksum Mismatch! Packet potentially corrupted.', 'error', true);
        highlightLayer('receiverIP', SIM_DELAY_LONG, true);
        // return; 
    } else {
        log('IP: Packet validated (Checksum OK), decapsulating TCP segment.', 'ip');
    }
    updateStatus('rxIpStatus', 'Ready');
    await sleep(SIM_DELAY_MEDIUM);

    // Transport Layer
    await highlightLayer('receiverTCP');
    updateStatus('rxTcpStatus', 'Processing');
    document.getElementById('rxTcpFrame').textContent = formatHexDisplay(tcpSegmentHex); // Show expected
    const tcpHeaderHexOnly = tcpSegmentHex.substring(0, 40); // 20 bytes header
    const appDataFromSegmentHex = tcpSegmentHex.substring(40);
    const parsedTcpHeader = parseTCPHeader(tcpHeaderHexOnly);
    displayHeaders('rxTcpHeaders', parsedTcpHeader);
    // TCP Checksum (Placeholder)
    const receivedTcpChecksum = parsedTcpHeader['Checksum'].substring(2);
    const pseudoSrcIp = ipToHex(srcIP); // Receiver uses original source as its pseudo-source for validation
    const pseudoDestIp = ipToHex(destIP);
    const pseudoProtocol = '00' + IP_PROTOCOL_TCP;
    const appDataLengthInSegment = appDataFromSegmentHex.length / 2;
    const tcpLengthForChecksum = (20 + appDataLengthInSegment).toString(16).padStart(4,'0');
    const pseudoHeaderForRx = pseudoSrcIp + pseudoDestIp + pseudoProtocol + tcpLengthForChecksum;

    const calculatedTcpChecksum = calculateTCPChecksum(pseudoHeaderForRx, tcpHeaderHexOnly, appDataFromSegmentHex);
    const tcpChecksumOk = receivedTcpChecksum.toLowerCase() === calculatedTcpChecksum.toLowerCase();

    document.getElementById('rxTcpChecksumStatus').textContent = `TCP Checksum Check: ${tcpChecksumOk ? 'OK' : 'FAIL'} (Rcv:0x${receivedTcpChecksum}, Calc:0x${calculatedTcpChecksum})`;
    if (!tcpChecksumOk) {
        log('TCP: Checksum Mismatch! Segment potentially corrupted.', 'error', true);
        highlightLayer('receiverTCP', SIM_DELAY_LONG, true);
        // return; 
    } else {
        log('TCP: Segment validated (Checksum OK), decapsulating application data.', 'tcp');
    }
    updateStatus('rxTcpStatus', 'ESTABLISHED'); // Remains established
    await sleep(SIM_DELAY_MEDIUM);

    // Application Layer
    await highlightLayer('receiverApp');
    updateStatus('rxAppStatus', 'Processing');
    const reconstructedData = hexToString(appDataFromSegmentHex);
    document.getElementById('rxOriginalData').textContent = reconstructedData;
    displayHeaders('rxHttpHeaders', parseHTTPHeaders(reconstructedData));
    if (reconstructedData === originalHttpData) {
        log('App: Data successfully reconstructed and matches original.', 'app');
        packetsReceivedCount++;
    } else {
        log('App: Data Mismatch! Reconstructed data does not match original.', 'error', true);
        highlightLayer('receiverApp', SIM_DELAY_LONG, true);
    }
    updateStatus('rxAppStatus', 'Complete');
}


// --- Simulation Control ---
function simulatePacketLoss() {
    isPacketLossActive = !isPacketLossActive;
    log(`Packet Loss Simulation: ${isPacketLossActive ? 'ACTIVATED (30% chance)' : 'DEACTIVATED'}`, 'sys');
    document.getElementById('lossBtn').textContent = isPacketLossActive ? "Disable Packet Loss" : "Simulate Packet Loss";
    document.getElementById('lossBtn').style.borderColor = isPacketLossActive ? "#ff0000" : "#00ff00";
}

function simulateCongestion() {
    log('Simulating Network Congestion event...', 'sys');
    // TCP Reacts to Congestion (Simplified: Fast Retransmit/Recovery not fully modeled)
    ssthresh = Math.max(2, Math.floor(congestionWindow / 2)); // Set ssthresh to half of current CWND
    congestionWindow = 1; // Reset CWND to 1 (or ssthresh depending on TCP variant for Fast Recovery)
    simulatedRTT = Math.min(500, simulatedRTT * 1.5); // Increase RTT, max 500ms
    log(`Congestion Detected! CWND reset to ${congestionWindow} MSS, SSThresh to ${ssthresh} MSS, RTT to ${simulatedRTT}ms.`, 'tcp');
    updateTCPState();
    updateNetworkStats();
}

function resetSimulation() {
    log('Resetting simulation environment...', 'sys');
    connectionState = 'CLOSED';
    clientSequenceNum = Math.floor(Math.random() * 100000);
    clientAckNum = 0;
    serverSequenceNum = 0;
    serverAckNum = 0;
    congestionWindow = 1;
    ssthresh = 64;
    simulatedRTT = 50;
    packetsSentCount = 0;
    packetsReceivedCount = 0;
    dataPacketsLostCount = 0;
    retransmissionsCount = 0;
    appDataSentBytes = 0;
    totalOverheadBytes = 0;
    isPacketLossActive = false;
    currentPacketId = 0;

    const displayIds = [
        'originalData', 'tcpFrame', 'ipPacket', 'ethFrame', 'physicalBits',
        'rxPhysicalBits', 'rxEthFrame', 'rxIpPacket', 'rxTcpFrame', 'rxOriginalData'
    ];
    displayIds.forEach(id => {
        const el = document.getElementById(id);
        if (id.startsWith('rx')) el.textContent = 'Waiting...';
        else if (id !== 'originalData') el.textContent = ''; // Don't clear original data input
    });
    
    const headerBreakdownIds = [
        'httpHeaders', 'tcpHeaders', 'ipHeaders', 'ethHeaders',
        'rxEthHeaders', 'rxIpHeaders', 'rxTcpHeaders', 'rxHttpHeaders'
    ];
    headerBreakdownIds.forEach(id => document.getElementById(id).innerHTML = '');

    const statusIds = {
        'appStatus': 'Ready', 'tcpStatus': 'CLOSED', 'ipStatus': 'Ready', 'ethStatus': 'Ready', 'phyStatus': 'Idle',
        'rxPhyStatus': 'Listening', 'rxEthStatus': 'Ready', 'rxIpStatus': 'Ready', 'rxTcpStatus': 'CLOSED', 'rxAppStatus': 'Waiting',
        'connectionStatus': 'Connection Status: Not Initialized',
        'ipChecksumStatus': 'IP Checksum: N/A', 'tcpChecksumStatus': 'TCP Checksum: N/A', 'ethChecksumStatus': 'Ethernet FCS: N/A',
        'rxIpChecksumStatus': 'IP Checksum Check: N/A', 'rxTcpChecksumStatus': 'TCP Checksum Check: N/A', 'rxEthChecksumStatus': 'Ethernet FCS Check: N/A'
    };
    for (const [id, text] of Object.entries(statusIds)) {
        updateStatus(id, text);
    }
    
    document.getElementById('initBtn').disabled = false;
    document.getElementById('sendBtn').disabled = true;
    document.getElementById('lossBtn').disabled = true;
    document.getElementById('lossBtn').textContent = "Simulate Packet Loss";
    document.getElementById('lossBtn').style.borderColor = "#00ff00";
    document.getElementById('congBtn').disabled = true;

    document.getElementById('movingPacket').style.display = 'none';
    document.getElementById('sequenceLog').innerHTML = '<div class="log-entry log-sys"><span class="timestamp"></span>System ready - Initialize connection to begin</div>';
    
    updateTCPState();
    updateNetworkStats();
    updateProtocolAnalysis();
}

// Initial setup
document.addEventListener('DOMContentLoaded', () => {
    resetSimulation(); // Initialize all displays
}); 