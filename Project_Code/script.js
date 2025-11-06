// =======================================================================
// GLOBAL STATE MANAGEMENT AND UI ELEMENTS
// =======================================================================

//  Get references to key UI elements for state management 
const connectionStatusSpan = document.getElementById('connection-status');
const statusDot = document.getElementById('status-dot');
const startButton = document.getElementById('start-button');
const stopButton = document.getElementById('stop-button');
const endSessionButton = document.getElementById('end-session-button');

//  Core Application State 
let isConnected = false;      // Is the WebSocket connected to the server?
let isCapturing = false;      // Is a capture currently running?
let currentSessionId = null;  // The ID of the currently active session.

/**
 * Updates the entire UI (buttons, status text) based on the current state.
 * This function is the single source of truth for the UI's appearance.
 */
function updateGuiState() {
    if (!isConnected) {
        statusDot.className = 'status-dot';
        connectionStatusSpan.textContent = 'Disconnected';
        connectionStatusSpan.className = 'text-sm font-medium text-red-400';
        startButton.disabled = true; startButton.classList.add('opacity-50');
        stopButton.disabled = true; stopButton.classList.add('opacity-50');
        endSessionButton.disabled = true; endSessionButton.classList.add('opacity-50');
    } else if (isCapturing) {
        statusDot.className = 'status-dot capturing';
        connectionStatusSpan.textContent = `Capturing (Session ${currentSessionId})...`;
        connectionStatusSpan.className = 'text-sm font-medium text-yellow-400';
        startButton.disabled = true; startButton.classList.add('opacity-50');
        stopButton.disabled = false; stopButton.classList.remove('opacity-50');
        endSessionButton.disabled = false; endSessionButton.classList.remove('opacity-50');
    } else { // Connected but idle
        statusDot.className = 'status-dot connected';
        connectionStatusSpan.textContent = 'Connected (Idle)';
        connectionStatusSpan.className = 'text-sm font-medium text-green-400';
        startButton.disabled = false; startButton.classList.remove('opacity-50');
        stopButton.disabled = true; stopButton.classList.add('opacity-50');
        // A session can be paused but not ended, so the "End Session" button should be active.
        endSessionButton.disabled = currentSessionId === null;
        if (currentSessionId === null) {
            endSessionButton.classList.add('opacity-50');
        } else {
            connectionStatusSpan.textContent = `Paused (Session ${currentSessionId})`;
            endSessionButton.classList.remove('opacity-50');
        }
    }
}

// =======================================================================
// GLOBAL VARIABLES AND CONSTANTS
// =======================================================================

//  WebSocket and Packet Log Configuration 
let websocket = null;
const WS_URL = 'ws://localhost:8765';
const MAX_PACKETS_DISPLAY = 1000; // Max rows in the live capture table.
const packetCache = []; // Stores the full JSON of the last X packets for the details modal.

//  Chart Objects 
let protocolChart = null, endpointChart = null, timelineChart = null, wifiChart = null,
    dataVolumeChart = null, serviceChart = null, activityTrendChart = null,
    globalProtocolChart = null, globalTopTalkersChart = null;

//  Live Statistics Counters 
let totalPacketCount = 0;
let totalDataVolume = 0;
let securityAlertCount = 0;
let bytesThisSecond = 0;

//  Get references to other key UI elements 
const packetTableBody = document.getElementById('packet-table-body');
const packetCountSpan = document.getElementById('packet-count');
const navButtons = document.querySelectorAll('.nav-button');
const packetDetailModal = document.getElementById('packet-detail-modal');
const modalTitle = document.getElementById('modal-title');
const modalBody = document.getElementById('modal-body');
const historyTableBody = document.getElementById('history-table-body');

//  Data Aggregation Objects 
const protocolCounts = {};      // For the protocol distribution chart.
const endpointStats = {};       // For "Top Talkers" charts (by packets and volume).
const wifiFrameCounts = {};     // For the Wi-Fi frame type chart.
const portCounts = {};          // For the "Top Services" chart.
const uniqueDevices = new Set(); // For the "Unique Devices" summary widget.

//  Chart and Graph Configuration 
const CHART_COLORS = ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#EC4899', '#6366F1', '#14B8A6'];
let network = null; // The vis.js network graph object.
const nodes = new vis.DataSet([]);
const edges = new vis.DataSet([]);

//  UI Performance Buffers 
let tableUpdateBuffer = []; // Batches packet rows to prevent redrawing the table too frequently.
let chartUpdateNeeded = false; // A flag to signal that charts need to be redrawn.

//  Wireless Environment Data 
const discoveredEnvNetworks = {};
const discoveredEnvDevices = {};

// =======================================================================
// CORE APPLICATION LOGIC
// =======================================================================

/**
 * Establishes the WebSocket connection and defines all event handlers.
 * This function acts as the main message router for the application.
 */
function connectWebSocket() {
    websocket = new WebSocket(WS_URL);

    // When the connection opens, update the UI and load saved alert settings.
    websocket.onopen = () => { isConnected = true; updateGuiState(); loadAlertSettings(); };

    // If the connection closes, update the UI and attempt to reconnect after 3 seconds.
    websocket.onclose = () => { isConnected = false; isCapturing = false; currentSessionId = null; updateGuiState(); setTimeout(connectWebSocket, 3000); };

    // If there's an error, close the connection (which will trigger the onclose handler).
    websocket.onerror = () => websocket.close();

    // The main message router. This function is called for every message from the server.
    websocket.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);

            // Route the message based on its 'type' property.
            if (data.type === 'interfaces') updateInterfaceList(data.data);
            else if (data.type === 'sessions_updated') updateHistoryList(data.data);
            else if (data.type === 'session_packets') loadSessionPackets(data.data);
            else if (data.type === 'global_analysis_data') updateGlobalAnalysisPage(data.data);
            else if (data.type === 'alert_triggered') handleAlertTriggered(data.data);
            else if (data.type === 'system_stats') updateSystemStats(data);
            else if (data.security_event) handleSecurityEvent(data.security_event);
            else if (data.status) { // Handle status updates from the server
                if (data.status === 'starting') { isCapturing = true; currentSessionId = data.session_id; updateGuiState(); }
                else if (data.status === 'stopped') { isCapturing = false; updateGuiState(); }
                else if (data.status === 'session_ended') { isCapturing = false; currentSessionId = null; updateGuiState(); }
            } else {
                // If no specific type, it's a live packet.
                handlePacket(data);
            }
        } catch (error) { console.error("Failed to parse message:", error); }
    };
}

/**
 * Sends the 'START' command to the backend to begin or resume a capture.
 */
function startCapture() {
    if (!websocket || websocket.readyState !== WebSocket.OPEN) return;
    // Only clear the display if this is a brand new session.
    if (!isCapturing && currentSessionId === null) {
       clearAllData();
    }
    const interfaceName = document.getElementById('interface-select').value;
    const filter = document.getElementById('filter-input').value;
    websocket.send(JSON.stringify({ action: 'START', interface: interfaceName, filter: filter}));
}

/**
 * Sends the 'STOP' command to the backend to pause the live sniffer.
 */
function stopCapture() {
    if (websocket && websocket.readyState === WebSocket.OPEN) { websocket.send(JSON.stringify({ action: 'STOP' })); }
    isCapturing = false;
    updateGuiState();
}

/**
 * Sends the 'END_SESSION' command to the backend to stop the sniffer and mark the session as finished.
 */
function endSession() {
    if (websocket && websocket.readyState === WebSocket.OPEN && currentSessionId !== null) {
        if (confirm(`Are you sure you want to end session ${currentSessionId}?`)) {
            websocket.send(JSON.stringify({ action: 'END_SESSION' }));
        }
    }
}

/**
 * Resets all UI elements and in-memory data stores to their initial state.
 */
function clearAllData() {
    // Clear tables and reset counters
    packetTableBody.innerHTML = ''; packetCache.length = 0; totalPacketCount = 0; totalDataVolume = 0; securityAlertCount = 0;
    packetCountSpan.textContent = 0; bytesThisSecond = 0;
    updateSummaryWidgets();
    clearAggregationData();

    // Destroy and recreate all charts to prevent memory leaks and visual artifacts.
    const charts = [protocolChart, endpointChart, timelineChart, wifiChart, dataVolumeChart, serviceChart, activityTrendChart, globalProtocolChart, globalTopTalkersChart];
    charts.forEach(chart => { if (chart) chart.destroy(); });
    document.getElementById('security-events-body').innerHTML = '';
    document.getElementById('alerts-log-body').innerHTML = '';
    
    // Clear the network graph.
    nodes.clear();
    edges.clear();
    
    // Re-initialize the charts.
    initCharts();
}

/**
 * The core function for processing a single packet object from the server.
 * @param {object} data The full packet object from the backend.
 */
function handlePacket(data) {
    // Increment counters.
    totalPacketCount++;
    packetCountSpan.textContent = totalPacketCount;
    totalDataVolume += data.summary.length;
    bytesThisSecond += data.summary.length;
    
    // Add the packet to the local cache for the details modal.
    packetCache.unshift(data);
    if (packetCache.length > MAX_PACKETS_DISPLAY) { packetCache.pop(); }

    // Add the packet to the table buffer to be rendered later.
    addPacketToTable(data.summary, totalPacketCount);

    // Update all aggregation statistics.
    const summary = data.summary;
    uniqueDevices.add(summary.source);
    uniqueDevices.add(summary.destination);
    updateSummaryWidgets();
    updateProtocolStats(summary.protocol);
    updateEndpointStats(summary.source, summary.length);
    updateEndpointStats(summary.destination, summary.length);
    if (summary.dport) { updatePortStats(summary.dport); }
    if (data.wireless_meta) { handleWirelessMeta(data.wireless_meta); }
    if (summary.protocol === 'WLAN') { updateWifiFrameStats(summary.info); }
    updateNetworkGraph(summary);
}

/**
 * Updates the four main summary cards on the dashboard.
 */
function updateSummaryWidgets() {
    document.getElementById('summary-packets').textContent = totalPacketCount.toLocaleString();
    document.getElementById('summary-data').textContent = `${(totalDataVolume / 1048576).toFixed(2)} MB`;
    document.getElementById('summary-devices').textContent = uniqueDevices.size;
    document.getElementById('summary-alerts').textContent = securityAlertCount;
}

/**
 * Creates an HTML table row for a packet and adds it to the rendering buffer.
 * @param {object} summary The summary part of the packet data.
 * @param {number} packetNumber The sequential number of the packet.
 */
function addPacketToTable(summary, packetNumber) {
    const row = document.createElement('tr');
    row.dataset.cacheIndex = 0; // The newest packet is always at index 0 of the cache.
    row.onclick = () => showPacketDetails(0);

    // Apply a CSS class for protocol-specific coloring.
    const protoClass = `proto-${summary.protocol.toLowerCase()}`;
    
    row.innerHTML = `<td>${packetNumber}</td><td class="whitespace-nowrap">${new Date(summary.time * 1000).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 })}</td><td><span class="${protoClass} font-bold">${summary.protocol}</span></td><td>${summary.source}</td><td>${summary.destination}</td><td>${summary.length}</td><td class="max-w-xs">${summary.info}</td>`;
    tableUpdateBuffer.push(row);
}

/**
 * Displays the deep packet inspection modal for a selected packet.
 * @param {number} cacheIndex The index of the packet in the `packetCache`.
 */
function showPacketDetails(cacheIndex) {
    const packetData = packetCache[cacheIndex];
    if (!packetData || !packetData.full_packet) { return; }

    const packetNumber = totalPacketCount - cacheIndex;
    modalTitle.textContent = `Details for Packet #${packetNumber}`;
    modalBody.innerHTML = '';
    
    // Dynamically build the collapsible tree view.
    const { full_packet } = packetData;
    for (const layerName in full_packet) {
        if (layerName === 'raw_payload') continue;
        const fields = full_packet[layerName];
        const details = document.createElement('details');
        details.open = true;
        const summaryElem = document.createElement('summary');
        summaryElem.textContent = layerName.split(':')[1].replace(/_/g, ' ').toUpperCase();
        details.appendChild(summaryElem);
        for (const [key, value] of Object.entries(fields)) {
            const fieldDiv = document.createElement('div');
            fieldDiv.className = 'field';
            fieldDiv.innerHTML = `<span class="field-key">${key}</span><span class="field-value">${value}</span>`;
            details.appendChild(fieldDiv);
        }
        modalBody.appendChild(details);
    }

    // Add the hexdump if it exists.
    if (full_packet.raw_payload) {
        const details = document.createElement('details');
        details.open = true;
        const summaryElem = document.createElement('summary');
        summaryElem.textContent = 'RAW PAYLOAD';
        details.appendChild(summaryElem);
        const pre = document.createElement('pre');
        pre.className = 'payload-hexdump';
        pre.textContent = full_packet.raw_payload;
        details.appendChild(pre);
        modalBody.appendChild(details);
    }
    packetDetailModal.classList.remove('hidden');
}

/**
 * Closes the deep packet inspection modal.
 */
function closePacketDetails() {
    packetDetailModal.classList.add('hidden');
}

/**
 * Filters the live capture log based on user input.
 */
function applyDisplayFilter() {
    const filterText = document.getElementById('display-filter-input').value.trim().toLowerCase();
    const rows = packetTableBody.children;
    for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        const packet = packetCache[i]?.summary;
        if (!packet) continue;
        const text = `${packet.protocol} ${packet.source} ${packet.destination} ${packet.info}`.toLowerCase();
        row.style.display = text.includes(filterText) ? '' : 'none';
    }
}

/**
 * Manages the visibility of pages and the active state of navigation buttons.
 * @param {string} pageId The ID of the page to show.
 */
function showPage(pageId) {
    document.querySelectorAll('.page-content').forEach(p => p.classList.add('hidden'));
    document.getElementById(`${pageId}-page`).classList.remove('hidden');
    navButtons.forEach(b => {
        b.classList.toggle('text-indigo-400', b.dataset.page === pageId);
        b.classList.toggle('bg-[#21262d]', b.dataset.page === pageId);
        b.classList.toggle('text-gray-400', b.dataset.page !== pageId);
    });
    // When switching to the Global Stats page, request the data from the backend.
    if (pageId === 'global-stats') {
        websocket.send(JSON.stringify({ action: 'GET_GLOBAL_ANALYSIS' }));
    }
}
navButtons.forEach(b => b.addEventListener('click', () => showPage(b.dataset.page)));

/**
 * Populates the network interface dropdown list.
 */
function updateInterfaceList(interfaces) {
    const select = document.getElementById('interface-select');
    select.innerHTML = '';
    interfaces.forEach(iface => {
        const option = document.createElement('option');
        option.value = iface;
        option.textContent = iface;
        if (iface.includes('mon')) option.selected = true;
        select.appendChild(option);
    });
}

/**
 * Populates the history table with session data from the server.
 */
function updateHistoryList(sessions) {
    historyTableBody.innerHTML = '';
    if (sessions.length === 0) { historyTableBody.innerHTML = '<tr><td colspan="5" class="text-center text-gray-500 py-4">No saved sessions found.</td></tr>'; return; }
    sessions.forEach(session => {
        const row = document.createElement('tr');
        const statusColor = session.status === 'Finished' ? 'text-green-400' : 'text-yellow-400';
        row.innerHTML = `<td class="py-2">${session.id}</td><td class="py-2">${session.start_time}</td><td class="py-2">${session.duration || '00:00:00'}</td><td class="py-2"><span class="${statusColor}">${session.status}</span></td><td class="text-right py-2"><button onclick="loadSession(${session.id})" class="text-blue-400 hover:underline px-2">Load</button><button onclick="event.stopPropagation(); downloadSession(${session.id})" class="text-green-400 hover:underline px-2">Download</button><button onclick="event.stopPropagation(); deleteSession(${session.id})" class="text-red-400 hover:underline px-2">Delete</button></td>`;
        historyTableBody.appendChild(row);
    });
}

/**
 * Requests all packets for a specific session ID from the backend.
 */
function loadSession(sessionId) {
    if (!websocket || websocket.readyState !== WebSocket.OPEN) return;
    clearAllData();
    showPage('dashboard');
    packetTableBody.innerHTML = '<tr><td colspan="7" class="text-center text-gray-500 py-4">Loading packets...</td></tr>';
    websocket.send(JSON.stringify({ action: 'GET_SESSION_PACKETS', session_id: sessionId }));
}

/**
 * Requests a session to be downloaded.
 */
function downloadSession(sessionId) {
    if (!websocket || websocket.readyState !== WebSocket.OPEN) return;
    websocket.send(JSON.stringify({ action: 'DOWNLOAD_SESSION', session_id: sessionId }));
}

/**
 * Takes the session data from the server and triggers a browser download.
 */
function triggerDownload(data) {
    const jsonData = JSON.stringify(data.data, null, 2);
    const blob = new Blob([jsonData], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    a.download = `session_${data.session_id}.json`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
}

/**
 * FIX: Re-processes all packets from a loaded session to populate all analysis pages.
 */
function loadSessionPackets(packets) {
    clearAllData();
    showPage('dashboard'); // Go to a neutral page to prevent visual glitches.
    setTimeout(() => {
        // Run every saved packet through the handler to rebuild all stats.
        packets.forEach(packet => {
            if (packet) handlePacket(packet);
        });
        // Switch to the capture log now that it's populated.
        showPage('live-capture');
    }, 100);
}

/**
 * Sends a command to delete a session from the database.
 */
function deleteSession(sessionId) {
    if (!websocket || websocket.readyState !== WebSocket.OPEN) return;
    if (confirm(`Are you sure you want to delete session ${sessionId}? This cannot be undone.`)) {
        websocket.send(JSON.stringify({ action: 'DELETE_SESSION', session_id: sessionId }));
    }
}

/**
 * Initializes all Chart.js instances.
 */
function initCharts() {
    Chart.defaults.color = '#9CA3AF';
    Chart.defaults.font.family = "'Inter', sans-serif";
    
    //  Chart Interactivity (Drill-Down) 
    const onChartClick = (event, elements) => {
        if (elements.length > 0) {
            const chart = elements[0].element.$context.chart;
            const label = chart.data.labels[elements[0].index];
            const ipAddress = label.split(' ')[0]; // Extract IP from label
            document.getElementById('display-filter-input').value = ipAddress;
            applyDisplayFilter();
            showPage('live-capture');
        }
    };
    const barOptionsWithClick = { indexAxis: 'y', responsive: true, maintainAspectRatio: false, scales: { y: { ticks: { autoSkip: false } } }, plugins: { legend: { display: false } }, onClick: onChartClick };
    const commonDoughnutOptions = { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { boxWidth: 12 } } } };

    //  Chart Definitions 
    timelineChart = new Chart(document.getElementById('timeline-chart').getContext('2d'), { type: 'line', data: { datasets: [{ label: 'Mbps', data: [], borderColor: CHART_COLORS[1], backgroundColor: CHART_COLORS[1] + '33', fill: true, tension: 0.3 }] }, options: { responsive: true, maintainAspectRatio: false, scales: { x: { type: 'time', time: { unit: 'second', displayFormats: { second: 'HH:mm:ss' } }, grid: { color: '#30363d' } }, y: { beginAtZero: true, grid: { color: '#30363d' }, ticks: { callback: function(value) { return value + ' Mbps'; } } } }, plugins: { legend: { display: false } } } });
    protocolChart = new Chart(document.getElementById('protocol-chart').getContext('2d'), { type: 'doughnut', data: { labels: [], datasets: [{ data: [], backgroundColor: CHART_COLORS, borderWidth: 0 }] }, options: commonDoughnutOptions });
    endpointChart = new Chart(document.getElementById('endpoint-chart').getContext('2d'), { type: 'bar', data: { labels: [], datasets: [{ label: 'Packets', data: [], backgroundColor: CHART_COLORS[0], borderWidth: 0 }] }, options: barOptionsWithClick });
    wifiChart = new Chart(document.getElementById('wifi-chart').getContext('2d'), { type: 'doughnut', data: { labels: [], datasets: [{ data: [], backgroundColor: [CHART_COLORS[2], CHART_COLORS[4], CHART_COLORS[5], CHART_COLORS[0], CHART_COLORS[6]], borderWidth: 0 }] }, options: commonDoughnutOptions });
    dataVolumeChart = new Chart(document.getElementById('data-volume-chart').getContext('2d'), { type: 'bar', data: { labels: [], datasets: [{ label: 'Megabytes', data: [], backgroundColor: CHART_COLORS[1], borderWidth: 0 }] }, options: barOptionsWithClick });
    serviceChart = new Chart(document.getElementById('service-chart').getContext('2d'), { type: 'bar', data: { labels: [], datasets: [{ label: 'Packets', data: [], backgroundColor: CHART_COLORS[4], borderWidth: 0 }] }, options: { ...barOptionsWithClick, onClick: null } }); // No click for service chart
    
    //  Global Stats Charts 
    activityTrendChart = new Chart(document.getElementById('activity-trend-chart').getContext('2d'), { type: 'line', data: { labels: [], datasets: [{ label: 'Packets', data: [], borderColor: CHART_COLORS[3], fill: false }] }, options: { responsive: true, maintainAspectRatio: false, scales: { x: { type: 'time', time: { unit: 'day' }, grid: { color: '#30363d' } }, y: { beginAtZero: true, grid: { color: '#30363d' } } }, plugins: { legend: { display: false } } } });
    globalProtocolChart = new Chart(document.getElementById('global-protocol-chart').getContext('2d'), { type: 'doughnut', data: { labels: [], datasets: [{ data: [], backgroundColor: CHART_COLORS, borderWidth: 0 }] }, options: commonDoughnutOptions });
    globalTopTalkersChart = new Chart(document.getElementById('global-top-talkers-chart').getContext('2d'), { type: 'bar', data: { labels: [], datasets: [{ label: 'Packets', data: [], backgroundColor: CHART_COLORS[0], borderWidth: 0 }] }, options: barOptionsWithClick });
}

// =======================================================================
// DATA UPDATE AND RENDERING FUNCTIONS
// =======================================================================

function updateSystemStats({ cpu, memory }) {
    const cpuGaugeText = document.getElementById('cpu-gauge-text');
    if(cpuGaugeText) {
        cpuGaugeText.textContent = `${cpu.toFixed(1)}%`;
        document.getElementById('cpu-gauge-bar').style.strokeDasharray = `${cpu}, 100`;
        document.getElementById('mem-gauge-text').textContent = `${memory.toFixed(1)}%`;
        document.getElementById('mem-gauge-bar').style.strokeDasharray = `${memory}, 100`;
    }
}

function updateTimelineChart() {
    if (!timelineChart || !isCapturing) return;
    const now = Date.now();
    const data = timelineChart.data.datasets[0].data;
    const megabitsPerSecond = (bytesThisSecond * 8) / 1000000;
    data.push({ x: now, y: megabitsPerSecond.toFixed(2) });
    bytesThisSecond = 0;
    if (data.length > 60) data.shift();
    timelineChart.update('quiet');
}

//  Data Aggregation Functions 
function updateProtocolStats(protocol) { if (!protocol || protocol === 'Unknown') return; protocolCounts[protocol] = (protocolCounts[protocol] || 0) + 1; chartUpdateNeeded = true; }
function updateWifiFrameStats(info) { let frameType = 'Other'; if (info.startsWith('Beacon')) frameType = 'Beacon'; else if (info.startsWith('Probe Request')) frameType = 'Probe Request'; else if (info.startsWith('Probe Response')) frameType = 'Probe Response'; else if (info.startsWith('Data') || info.startsWith('QoS')) frameType = 'Data'; else if (info.startsWith('Control')) frameType = 'Control'; wifiFrameCounts[frameType] = (wifiFrameCounts[frameType] || 0) + 1; chartUpdateNeeded = true; }
function updatePortStats(port) { if (!port) return; portCounts[port] = (portCounts[port] || 0) + 1; chartUpdateNeeded = true; }
function updateEndpointStats(endpoint, length) { if (!endpoint || endpoint === 'N/A' || endpoint === 'ff:ff:ff:ff:ff:ff') return; if (!endpointStats[endpoint]) endpointStats[endpoint] = { packets: 0, bytes: 0 }; endpointStats[endpoint].packets += 1; endpointStats[endpoint].bytes += parseInt(length) || 0; chartUpdateNeeded = true; }

//  Specific Page Update Functions 
function handleSecurityEvent(event) {
    securityAlertCount++;
    updateSummaryWidgets();
    const tableBody = document.getElementById('security-events-body');
    const row = document.createElement('tr');
    row.innerHTML = `<td class="py-2">${new Date(event.time * 1000).toLocaleTimeString()}</td><td class="py-2 text-red-400">${event.type}</td><td class="py-2">${event.message}</td>`;
    tableBody.prepend(row);
}

function updateGlobalAnalysisPage(data) {
    document.getElementById('global-packets').textContent = data.summary.total_packets.toLocaleString();
    document.getElementById('global-data').textContent = `${data.summary.total_data_gb.toLocaleString()} GB`;
    document.getElementById('global-sessions').textContent = data.summary.total_sessions.toLocaleString();
    
    activityTrendChart.data.labels = data.activity_by_day.map(d => d.day);
    activityTrendChart.data.datasets[0].data = data.activity_by_day.map(d => d.packet_count);
    activityTrendChart.update();

    globalTopTalkersChart.data.labels = data.top_talkers.map(t => t.talker);
    globalTopTalkersChart.data.datasets[0].data = data.top_talkers.map(t => t.packet_count);
    globalTopTalkersChart.update();

    globalProtocolChart.data.labels = data.protocol_dist.map(p => p.protocol);
    globalProtocolChart.data.datasets[0].data = data.protocol_dist.map(p => p.packet_count);
    globalProtocolChart.update();
}

function handleAlertTriggered(data) {
    const tableBody = document.getElementById('alerts-log-body');
    const row = document.createElement('tr');
    row.innerHTML = `<td class="py-2">${new Date().toLocaleTimeString()}</td><td class="py-2 text-yellow-400">${data.type}</td><td class="py-2">${data.message}</td>`;
    tableBody.prepend(row);
}

function saveAlertSettings() {
    const thresholds = {
        cpu: parseInt(document.getElementById('alert-cpu-threshold').value),
        throughput: parseInt(document.getElementById('alert-throughput-threshold').value),
        deauthAttack: document.getElementById('alert-deauth-checkbox').checked,
        arpSpoofing: document.getElementById('alert-arp-checkbox').checked
    };
    // Save settings to the browser's local storage for persistence.
    localStorage.setItem('alertThresholds', JSON.stringify(thresholds));
    // Send the new settings to the backend.
    if (websocket && websocket.readyState === WebSocket.OPEN) {
        websocket.send(JSON.stringify({ action: 'UPDATE_ALERT_THRESHOLDS', thresholds: thresholds }));
    }
    document.getElementById('save-alerts-button').textContent = 'Saved!';
    setTimeout(() => { document.getElementById('save-alerts-button').textContent = 'Save Settings'; }, 2000);
}

function loadAlertSettings() {
    const saved = localStorage.getItem('alertThresholds');
    if (saved) {
        const thresholds = JSON.parse(saved);
        document.getElementById('alert-cpu-threshold').value = thresholds.cpu;
        document.getElementById('alert-throughput-threshold').value = thresholds.throughput;
        document.getElementById('alert-deauth-checkbox').checked = thresholds.deauthAttack;
        document.getElementById('alert-arp-checkbox').checked = thresholds.arpSpoofing;
        // Send saved settings to the backend as soon as the connection is ready.
        if (websocket && websocket.readyState === WebSocket.OPEN) {
            websocket.send(JSON.stringify({ action: 'UPDATE_ALERT_THRESHOLDS', thresholds: thresholds }));
        }
    }
    // Attach the save function to the button's click event.
    document.getElementById('save-alerts-button').addEventListener('click', saveAlertSettings);
}

/**
 * Redraws all charts with the latest aggregated data. Called periodically by setInterval.
 */
function renderChartUpdates() {
    if (!chartUpdateNeeded) return;
    const portMap = { 80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 22: 'SSH', 21: 'FTP', 25: 'SMTP', 123: 'NTP' };
    
    // Update each chart with its sorted and sliced data.
    const sortedProtocols = Object.entries(protocolCounts).sort(([, a], [, b]) => b - a).slice(0, 8);
    protocolChart.data.labels = sortedProtocols.map(e => e[0]);
    protocolChart.data.datasets[0].data = sortedProtocols.map(e => e[1]);
    protocolChart.update();

    const sortedEndpoints = Object.entries(endpointStats).sort(([, a], [, b]) => b.packets - a.packets).slice(0, 10);
    endpointChart.data.labels = sortedEndpoints.map(e => e[0]);
    endpointChart.data.datasets[0].data = sortedEndpoints.map(e => e[1].packets);
    endpointChart.update();

    const sortedVolume = Object.entries(endpointStats).sort(([, a], [, b]) => b.bytes - a.bytes).slice(0, 10);
    dataVolumeChart.data.labels = sortedVolume.map(e => e[0]);
    dataVolumeChart.data.datasets[0].data = sortedVolume.map(e => (e[1].bytes / 1048576).toFixed(2));
    dataVolumeChart.update();
    
    const sortedPorts = Object.entries(portCounts).sort(([, a], [, b]) => b - a).slice(0, 10);
    serviceChart.data.labels = sortedPorts.map(e => portMap[e[0]] ? `${portMap[e[0]]} (${e[0]})` : e[0]);
    serviceChart.data.datasets[0].data = sortedPorts.map(e => e[1]);
    serviceChart.update();

    const sortedWifi = Object.entries(wifiFrameCounts).sort(([, a], [, b]) => b - a);
    wifiChart.data.labels = sortedWifi.map(e => e[0]);
    wifiChart.data.datasets[0].data = sortedWifi.map(e => e[1]);
    wifiChart.update();

    chartUpdateNeeded = false;
}

// ... (Wireless environment and network graph functions are unchanged) ...
function handleWirelessMeta(meta) {
    const now = new Date().toLocaleTimeString();
    if (meta.type === 'beacon') { discoveredEnvNetworks[meta.bssid] = { ssid: meta.ssid, bssid: meta.bssid, channel: meta.channel, lastSeen: now }; updateEnvNetworksTable(); } 
    else if (meta.type === 'probe_req') { if (!discoveredEnvDevices[meta.client_mac]) { discoveredEnvDevices[meta.client_mac] = { mac: meta.client_mac, probingFor: new Set(), lastSeen: now }; } const device = discoveredEnvDevices[meta.client_mac]; device.probingFor.add(meta.probed_ssid); device.lastSeen = now; updateEnvDevicesTable(); }
}
function updateEnvNetworksTable() { let html = ''; Object.values(discoveredEnvNetworks).sort((a,b) => a.ssid.localeCompare(b.ssid)).forEach(n => { html += `<tr><td>${n.ssid}</td><td>${n.bssid}</td><td>${n.channel}</td><td>${n.lastSeen}</td></tr>`; }); document.getElementById('env-networks-body').innerHTML = html; }
function updateEnvDevicesTable() { let html = ''; Object.values(discoveredEnvDevices).forEach(c => { html += `<tr><td>${c.mac}</td><td class="max-w-xs">${Array.from(c.probingFor).join(', ')}</td><td>${c.lastSeen}</td></tr>`; }); document.getElementById('env-devices-body').innerHTML = html; }
function initNetworkGraph() { const container = document.getElementById('network-graph-container'); const data = { nodes: nodes, edges: edges }; const options = { nodes: { shape: 'dot', size: 16, font: { color: '#c9d1d9', size: 12 }, borderWidth: 2, }, edges: { width: 2, color: { inherit: 'from' }, smooth: { type: 'continuous' } }, physics: { enabled: true, barnesHut: { gravitationalConstant: -20000, springConstant: 0.04, springLength: 200, avoidOverlap: 0.1 }, stabilization: { iterations: 150 } }, interaction: { tooltipDelay: 100, hideEdgesOnDrag: true }, layout: { improvedLayout: false } }; network = new vis.Network(container, data, options); }
function updateNetworkGraph(summary) {
    const { source, destination } = summary; if (!source || !destination || source === 'N/A' || destination === 'N/A' || destination.toLowerCase() === 'ff:ff:ff:ff:ff:ff') return;
    if (!nodes.get(source)) { nodes.add({ id: source, label: source }); } if (!nodes.get(destination)) { nodes.add({ id: destination, label: destination }); }
    const edgeId = [source, destination].sort().join('-'); const existingEdge = edges.get(edgeId);
    if (existingEdge) { edges.update({ id: existingEdge.id, value: (existingEdge.value || 1) + 1 }); } else { edges.add({ id: edgeId, from: source, to: destination, value: 1 }); }
}
function clearAggregationData() {
    for (const key in protocolCounts) delete protocolCounts[key]; for (const key in endpointStats) delete endpointStats[key];
    for (const key in discoveredEnvNetworks) delete discoveredEnvNetworks[key]; for (const key in discoveredEnvDevices) delete discoveredEnvDevices[key];
    for (const key in wifiFrameCounts) delete wifiFrameCounts[key]; for (const key in portCounts) delete portCounts[key];
    uniqueDevices.clear();
    document.getElementById('env-networks-body').innerHTML = ''; document.getElementById('env-devices-body').innerHTML = '';
}

// =======================================================================
// INITIALIZATION
// =======================================================================

/**
 * This function runs once the entire page has loaded.
 */
document.addEventListener('DOMContentLoaded', () => {
    // Start the core application logic.
    connectWebSocket();
    showPage('dashboard');
    initCharts();
    initNetworkGraph();
    updateGuiState();
    loadAlertSettings(); // Load and apply saved alert settings.
    
    const autoScrollCheckbox = document.getElementById('auto-scroll-checkbox');

    // Set up a periodic timer to render the live packet table.
    setInterval(() => {
        if (tableUpdateBuffer.length === 0) return;
        if (autoScrollCheckbox.checked) {
            const fragment = document.createDocumentFragment();
            packetTableBody.prepend(...tableUpdateBuffer);
            while (packetTableBody.children.length > MAX_PACKETS_DISPLAY) {
                packetTableBody.removeChild(packetTableBody.lastChild);
            }
            tableUpdateBuffer = [];
            applyDisplayFilter();
        }
    }, 500);

    // Set up periodic timers to update the charts and live throughput graph.
    setInterval(renderChartUpdates, 1000);
    setInterval(updateTimelineChart, 1000);
});
