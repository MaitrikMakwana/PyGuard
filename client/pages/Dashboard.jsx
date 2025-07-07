import { useState, useEffect, useRef } from "react";
import Navigation from "../components/Navigation";

const Dashboard = () => {
  const [user, setUser] = useState(null);
  const [activeTab, setActiveTab] = useState("live");
  const [isCapturing, setIsCapturing] = useState(false);
  const [selectedInterface, setSelectedInterface] = useState("eth0");
  const [packets, setPackets] = useState([]);
  const [filteredPackets, setFilteredPackets] = useState([]);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [filterExpression, setFilterExpression] = useState("");
  const [filterError, setFilterError] = useState("");
  const [sortField, setSortField] = useState("timestamp");
  const [sortOrder, setSortOrder] = useState("desc");
  const [currentPage, setCurrentPage] = useState(1);
  const [packetsPerPage, setPacketsPerPage] = useState(50);
  const [packetLimit, setPacketLimit] = useState(1000);
  const [showFilterHelp, setShowFilterHelp] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [exportFormat, setExportFormat] = useState("json");
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({
    totalPackets: 0,
    threatsDetected: 0,
    bytesProcessed: 0,
    uptime: "00:00:00",
    protocolStats: {},
    topTalkers: {},
  });

  const packetTableRef = useRef(null);
  const captureStartTime = useRef(null);

  // Check for user session
  useEffect(() => {
    const savedUser = localStorage.getItem("pyguard_user");
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }
  }, []);

  // Packet capture simulation
  useEffect(() => {
    let interval;
    if (isCapturing && packets.length < packetLimit) {
      interval = setInterval(
        () => {
          const newPacket = generateAdvancedPacket();
          setPackets((prev) => {
            const updated = [newPacket, ...prev];
            return updated.slice(0, packetLimit);
          });
          updateStats(newPacket);
        },
        Math.random() * 500 + 200,
      );
    }
    return () => clearInterval(interval);
  }, [isCapturing, packets.length, packetLimit]);

  // Filter packets based on expression
  useEffect(() => {
    if (!filterExpression.trim()) {
      setFilteredPackets(packets);
      setFilterError("");
      return;
    }

    try {
      const filtered = packets.filter((packet) => {
        return evaluateFilter(packet, filterExpression);
      });
      setFilteredPackets(filtered);
      setFilterError("");
    } catch (error) {
      setFilterError(error.message);
      setFilteredPackets(packets);
    }
  }, [packets, filterExpression]);

  // Sort packets
  useEffect(() => {
    const sorted = [...filteredPackets].sort((a, b) => {
      let aVal = a[sortField];
      let bVal = b[sortField];

      if (sortField === "size") {
        aVal = parseInt(aVal);
        bVal = parseInt(bVal);
      } else if (sortField === "timestamp") {
        aVal = new Date(aVal).getTime();
        bVal = new Date(bVal).getTime();
      }

      if (sortOrder === "asc") {
        return aVal > bVal ? 1 : -1;
      } else {
        return aVal < bVal ? 1 : -1;
      }
    });
    setFilteredPackets(sorted);
  }, [sortField, sortOrder]);

  // Uptime counter
  useEffect(() => {
    let uptimeInterval;
    if (isCapturing) {
      if (!captureStartTime.current) {
        captureStartTime.current = Date.now();
      }
      uptimeInterval = setInterval(() => {
        const elapsed = Math.floor(
          (Date.now() - captureStartTime.current) / 1000,
        );
        const hours = Math.floor(elapsed / 3600)
          .toString()
          .padStart(2, "0");
        const minutes = Math.floor((elapsed % 3600) / 60)
          .toString()
          .padStart(2, "0");
        const seconds = (elapsed % 60).toString().padStart(2, "0");
        setStats((prev) => ({
          ...prev,
          uptime: `${hours}:${minutes}:${seconds}`,
        }));
      }, 1000);
    }
    return () => clearInterval(uptimeInterval);
  }, [isCapturing]);

  const generateAdvancedPacket = () => {
    const protocols = [
      "TCP",
      "UDP",
      "HTTP",
      "HTTPS",
      "FTP",
      "SSH",
      "DNS",
      "ICMP",
    ];
    const sources = [
      "192.168.1.100",
      "10.0.0.50",
      "172.16.1.25",
      "203.0.113.10",
      "8.8.8.8",
    ];
    const destinations = [
      "8.8.8.8",
      "1.1.1.1",
      "192.168.1.1",
      "10.0.0.1",
      "172.16.1.1",
    ];
    const threatTypes = [
      "Port Scan",
      "SQL Injection",
      "DDoS Attempt",
      "Malware",
      "Brute Force",
    ];

    const protocol = protocols[Math.floor(Math.random() * protocols.length)];
    const source = sources[Math.floor(Math.random() * sources.length)];
    const destination =
      destinations[Math.floor(Math.random() * destinations.length)];
    const isThreat = Math.random() < 0.1;
    const size = Math.floor(Math.random() * 1500) + 64;

    return {
      id: Date.now() + Math.random(),
      timestamp: new Date().toISOString(),
      sourceIp: source,
      destinationIp: destination,
      protocol: protocol.toLowerCase(),
      sourcePort: Math.floor(Math.random() * 65535) + 1,
      destinationPort: Math.floor(Math.random() * 65535) + 1,
      size: size,
      threat: isThreat,
      threatType: isThreat
        ? threatTypes[Math.floor(Math.random() * threatTypes.length)]
        : null,
      severity: isThreat
        ? ["Low", "Medium", "High", "Critical"][Math.floor(Math.random() * 4)]
        : null,
      details: {
        ttl: Math.floor(Math.random() * 255) + 1,
        flags: generateTcpFlags(),
        checksum: generateChecksum(),
        payload: generatePayload(protocol),
        headers: generateHeaders(protocol),
      },
    };
  };

  const generateTcpFlags = () => {
    const flags = [];
    if (Math.random() < 0.3) flags.push("SYN");
    if (Math.random() < 0.3) flags.push("ACK");
    if (Math.random() < 0.1) flags.push("FIN");
    if (Math.random() < 0.05) flags.push("RST");
    return flags.join(",");
  };

  const generateChecksum = () => {
    return (
      "0x" +
      Math.floor(Math.random() * 65535)
        .toString(16)
        .toUpperCase()
        .padStart(4, "0")
    );
  };

  const generatePayload = (protocol) => {
    const payloads = {
      http: "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n",
      https: "[Encrypted Data]",
      ftp: "USER anonymous\\r\\n",
      ssh: "[SSH Handshake]",
      dns: "Query: example.com Type: A",
    };
    return payloads[protocol.toLowerCase()] || "[Binary Data]";
  };

  const generateHeaders = (protocol) => {
    return {
      ethernet: {
        source: generateMac(),
        destination: generateMac(),
        type: "0x0800",
      },
      ip: {
        version: 4,
        headerLength: 20,
        typeOfService: 0,
        identification: Math.floor(Math.random() * 65535),
      },
      [protocol.toLowerCase()]: {
        sequenceNumber: Math.floor(Math.random() * 4294967295),
        acknowledgmentNumber: Math.floor(Math.random() * 4294967295),
      },
    };
  };

  const generateMac = () => {
    return Array.from({ length: 6 }, () =>
      Math.floor(Math.random() * 256)
        .toString(16)
        .padStart(2, "0"),
    ).join(":");
  };

  const updateStats = (packet) => {
    setStats((prev) => ({
      ...prev,
      totalPackets: prev.totalPackets + 1,
      bytesProcessed: prev.bytesProcessed + packet.size,
      threatsDetected: prev.threatsDetected + (packet.threat ? 1 : 0),
      protocolStats: {
        ...prev.protocolStats,
        [packet.protocol]: (prev.protocolStats[packet.protocol] || 0) + 1,
      },
      topTalkers: {
        ...prev.topTalkers,
        [packet.sourceIp]: (prev.topTalkers[packet.sourceIp] || 0) + 1,
      },
    }));

    if (packet.threat) {
      const alert = {
        id: Date.now(),
        type: packet.threatType,
        source: packet.sourceIp,
        target: packet.destinationIp,
        timestamp: new Date().toLocaleTimeString(),
        severity: packet.severity,
      };
      setAlerts((prev) => [alert, ...prev.slice(0, 9)]);
    }
  };

  const evaluateFilter = (packet, expression) => {
    // Simple filter evaluation - supports basic expressions
    const filters = expression.toLowerCase().split(/\s*(and|or|\|\||&&)\s*/);

    for (let filter of filters) {
      if (
        filter === "and" ||
        filter === "or" ||
        filter === "||" ||
        filter === "&&"
      )
        continue;

      if (filter.includes("ip.src")) {
        const value = filter.split(/[=<>!]+/)[1]?.trim();
        if (value && !packet.sourceIp.includes(value)) return false;
      } else if (filter.includes("ip.dst")) {
        const value = filter.split(/[=<>!]+/)[1]?.trim();
        if (value && !packet.destinationIp.includes(value)) return false;
      } else if (filter.includes("tcp.port") || filter.includes("udp.port")) {
        const value = filter.split(/[=<>!]+/)[1]?.trim();
        if (
          value &&
          packet.sourcePort !== parseInt(value) &&
          packet.destinationPort !== parseInt(value)
        )
          return false;
      } else if (filter.includes("protocol")) {
        const value = filter.split(/[=<>!]+/)[1]?.trim();
        if (value && !packet.protocol.includes(value)) return false;
      }
    }
    return true;
  };

  const toggleCapture = () => {
    if (!isCapturing) {
      captureStartTime.current = Date.now();
    } else {
      captureStartTime.current = null;
    }
    setIsCapturing(!isCapturing);
  };

  const clearPackets = () => {
    setPackets([]);
    setFilteredPackets([]);
    setSelectedPacket(null);
    setAlerts([]);
    setStats({
      totalPackets: 0,
      threatsDetected: 0,
      bytesProcessed: 0,
      uptime: "00:00:00",
      protocolStats: {},
      topTalkers: {},
    });
  };

  const exportPackets = () => {
    setIsLoading(true);
    setTimeout(() => {
      const data = filteredPackets.slice(
        (currentPage - 1) * packetsPerPage,
        currentPage * packetsPerPage,
      );
      let content, filename, mimeType;

      switch (exportFormat) {
        case "csv":
          content = generateCSV(data);
          filename = "packets.csv";
          mimeType = "text/csv";
          break;
        case "json":
          content = JSON.stringify(data, null, 2);
          filename = "packets.json";
          mimeType = "application/json";
          break;
        case "pcap":
          content = "PCAP export not implemented in demo";
          filename = "packets.pcap";
          mimeType = "application/octet-stream";
          break;
        default:
          content = JSON.stringify(data, null, 2);
          filename = "packets.json";
          mimeType = "application/json";
      }

      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
      setIsLoading(false);
    }, 1000);
  };

  const generateCSV = (data) => {
    const headers = [
      "Timestamp",
      "Source IP",
      "Destination IP",
      "Protocol",
      "Source Port",
      "Destination Port",
      "Size",
      "Threat",
    ];
    const rows = data.map((packet) => [
      packet.timestamp,
      packet.sourceIp,
      packet.destinationIp,
      packet.protocol,
      packet.sourcePort,
      packet.destinationPort,
      packet.size,
      packet.threat ? "Yes" : "No",
    ]);
    return [headers, ...rows].map((row) => row.join(",")).join("\n");
  };

  const currentPackets = filteredPackets.slice(
    (currentPage - 1) * packetsPerPage,
    currentPage * packetsPerPage,
  );

  const totalPages = Math.ceil(filteredPackets.length / packetsPerPage);

  const interfaces = [
    { value: "eth0", label: "Ethernet (eth0)" },
    { value: "wlan0", label: "WiFi (wlan0)" },
    { value: "lo", label: "Loopback (lo)" },
    { value: "any", label: "Any Interface" },
  ];

  return (
    <div className="min-h-screen bg-slate-900">
      <Navigation />

      <div className="pt-20">
        {/* Header */}
        <div className="bg-slate-800/50 border-b border-gray-700">
          <div className="container-custom py-6">
            <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center">
              <div>
                <h1 className="text-3xl font-bold text-white mb-2">
                  {user ? `${user.name.split(" ")[0]}'s` : "PyGuard Pro"}{" "}
                  <span className="gradient-text">Packet Analyzer</span>
                </h1>
                <p className="text-gray-400">
                  Advanced network packet capture and analysis platform
                </p>
              </div>

              {/* Capture Controls */}
              <div className="flex flex-wrap items-center gap-4 mt-4 lg:mt-0">
                <select
                  value={selectedInterface}
                  onChange={(e) => setSelectedInterface(e.target.value)}
                  className="px-3 py-2 bg-slate-700 border border-gray-600 rounded-lg text-white text-sm"
                  disabled={isCapturing}
                >
                  {interfaces.map((iface) => (
                    <option key={iface.value} value={iface.value}>
                      {iface.label}
                    </option>
                  ))}
                </select>

                <input
                  type="number"
                  value={packetLimit}
                  onChange={(e) =>
                    setPacketLimit(parseInt(e.target.value) || 1000)
                  }
                  placeholder="Packet Limit"
                  className="w-24 px-3 py-2 bg-slate-700 border border-gray-600 rounded-lg text-white text-sm"
                  disabled={isCapturing}
                />

                <button
                  onClick={toggleCapture}
                  className={`px-6 py-2 rounded-lg font-medium transition-all duration-300 ${
                    isCapturing
                      ? "bg-red-600 hover:bg-red-700 text-white"
                      : "bg-green-600 hover:bg-green-700 text-white"
                  }`}
                >
                  {isCapturing ? "Stop Capture" : "Start Capture"}
                </button>

                <button onClick={clearPackets} className="btn-secondary py-2">
                  Clear
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="container-custom py-6">
          <div className="grid grid-cols-2 lg:grid-cols-6 gap-4 mb-6">
            <div className="glass-effect rounded-lg p-4">
              <div className="text-2xl font-bold text-blue-400 mb-1">
                {stats.totalPackets.toLocaleString()}
              </div>
              <div className="text-gray-400 text-sm">Total Packets</div>
            </div>
            <div className="glass-effect rounded-lg p-4">
              <div className="text-2xl font-bold text-red-400 mb-1">
                {stats.threatsDetected}
              </div>
              <div className="text-gray-400 text-sm">Threats</div>
            </div>
            <div className="glass-effect rounded-lg p-4">
              <div className="text-2xl font-bold text-green-400 mb-1">
                {(stats.bytesProcessed / 1024).toFixed(1)}KB
              </div>
              <div className="text-gray-400 text-sm">Data</div>
            </div>
            <div className="glass-effect rounded-lg p-4">
              <div className="text-2xl font-bold text-purple-400 mb-1">
                {stats.uptime}
              </div>
              <div className="text-gray-400 text-sm">Uptime</div>
            </div>
            <div className="glass-effect rounded-lg p-4">
              <div className="text-2xl font-bold text-yellow-400 mb-1">
                {Object.keys(stats.protocolStats).length}
              </div>
              <div className="text-gray-400 text-sm">Protocols</div>
            </div>
            <div className="glass-effect rounded-lg p-4">
              <div className="text-2xl font-bold text-cyan-400 mb-1">
                {Object.keys(stats.topTalkers).length}
              </div>
              <div className="text-gray-400 text-sm">Hosts</div>
            </div>
          </div>

          {/* Tab Navigation */}
          <div className="flex space-x-1 mb-6">
            {[
              { id: "live", label: "Live Capture" },
              { id: "analysis", label: "Analysis" },
              { id: "alerts", label: "Security Alerts" },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-2 rounded-lg font-medium transition-all duration-200 ${
                  activeTab === tab.id
                    ? "bg-blue-600 text-white"
                    : "bg-slate-700/50 text-gray-300 hover:bg-slate-700"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Main Content */}
          {activeTab === "live" && (
            <div className="grid lg:grid-cols-4 gap-6">
              {/* Packet Table */}
              <div className="lg:col-span-3">
                <div className="glass-effect rounded-xl">
                  {/* Filter Bar */}
                  <div className="p-4 border-b border-gray-700">
                    <div className="flex flex-col sm:flex-row gap-4">
                      <div className="flex-1">
                        <div className="relative">
                          <input
                            type="text"
                            value={filterExpression}
                            onChange={(e) =>
                              setFilterExpression(e.target.value)
                            }
                            placeholder="Filter expression (e.g., ip.src==192.168.1.1 or tcp.port==80)"
                            className="w-full px-4 py-2 bg-slate-800/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:border-blue-500 focus:outline-none"
                          />
                          <button
                            onClick={() => setShowFilterHelp(!showFilterHelp)}
                            className="absolute right-2 top-2 text-gray-400 hover:text-white"
                          >
                            <svg
                              className="w-5 h-5"
                              fill="none"
                              stroke="currentColor"
                              viewBox="0 0 24 24"
                            >
                              <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2}
                                d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                              />
                            </svg>
                          </button>
                        </div>
                        {filterError && (
                          <p className="text-red-400 text-sm mt-1">
                            {filterError}
                          </p>
                        )}
                      </div>

                      <div className="flex gap-2">
                        <select
                          value={sortField}
                          onChange={(e) => setSortField(e.target.value)}
                          className="px-3 py-2 bg-slate-700 border border-gray-600 rounded-lg text-white text-sm"
                        >
                          <option value="timestamp">Time</option>
                          <option value="sourceIp">Source IP</option>
                          <option value="destinationIp">Dest IP</option>
                          <option value="protocol">Protocol</option>
                          <option value="size">Size</option>
                        </select>

                        <button
                          onClick={() =>
                            setSortOrder(sortOrder === "asc" ? "desc" : "asc")
                          }
                          className="px-3 py-2 bg-slate-700 border border-gray-600 rounded-lg text-white hover:bg-slate-600"
                        >
                          {sortOrder === "asc" ? "↑" : "↓"}
                        </button>

                        <button
                          onClick={() => setFilterExpression("")}
                          className="px-3 py-2 bg-slate-700 border border-gray-600 rounded-lg text-white hover:bg-slate-600"
                        >
                          Clear
                        </button>
                      </div>
                    </div>

                    {/* Filter Help */}
                    {showFilterHelp && (
                      <div className="mt-4 p-4 bg-slate-800/50 rounded-lg">
                        <h4 className="text-white font-medium mb-2">
                          Filter Syntax Examples:
                        </h4>
                        <ul className="text-gray-300 text-sm space-y-1">
                          <li>
                            <code>ip.src==192.168.1.1</code> - Source IP equals
                          </li>
                          <li>
                            <code>ip.dst==8.8.8.8</code> - Destination IP equals
                          </li>
                          <li>
                            <code>tcp.port==80</code> - TCP port 80 (source or
                            dest)
                          </li>
                          <li>
                            <code>protocol==tcp</code> - TCP protocol only
                          </li>
                          <li>
                            <code>ip.src==192.168.1.1 and tcp.port==80</code> -
                            Multiple conditions
                          </li>
                        </ul>
                      </div>
                    )}
                  </div>

                  {/* Packet Table */}
                  <div className="h-96 overflow-hidden">
                    <div className="bg-slate-800/30 border-b border-gray-700 p-3">
                      <div className="grid grid-cols-8 gap-2 text-sm font-medium text-gray-400">
                        <div>Time</div>
                        <div>Source IP</div>
                        <div>Dest IP</div>
                        <div>Protocol</div>
                        <div>Src Port</div>
                        <div>Dst Port</div>
                        <div>Size</div>
                        <div>Info</div>
                      </div>
                    </div>

                    <div
                      className="h-80 overflow-y-auto scrollbar-thin scrollbar-thumb-gray-600"
                      ref={packetTableRef}
                    >
                      {currentPackets.length === 0 ? (
                        <div className="flex items-center justify-center h-full text-gray-400">
                          <div className="text-center">
                            <svg
                              className="w-12 h-12 mx-auto mb-4 opacity-50"
                              fill="none"
                              stroke="currentColor"
                              viewBox="0 0 24 24"
                            >
                              <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2}
                                d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"
                              />
                            </svg>
                            <p>
                              {isCapturing
                                ? "Waiting for packets..."
                                : "Start capture to monitor network traffic"}
                            </p>
                          </div>
                        </div>
                      ) : (
                        <div className="space-y-1 p-2">
                          {currentPackets.map((packet) => (
                            <div
                              key={packet.id}
                              onClick={() => setSelectedPacket(packet)}
                              className={`grid grid-cols-8 gap-2 p-2 rounded-lg cursor-pointer transition-colors ${
                                packet.threat
                                  ? "bg-red-900/20 border-l-2 border-red-500"
                                  : "hover:bg-slate-800/50"
                              } ${selectedPacket?.id === packet.id ? "bg-blue-900/30" : ""}`}
                            >
                              <div className="text-gray-300 text-xs">
                                {new Date(
                                  packet.timestamp,
                                ).toLocaleTimeString()}
                              </div>
                              <div className="text-gray-300 font-mono text-xs">
                                {packet.sourceIp}
                              </div>
                              <div className="text-gray-300 font-mono text-xs">
                                {packet.destinationIp}
                              </div>
                              <div>
                                <span className="bg-blue-600/20 text-blue-400 px-2 py-1 rounded text-xs uppercase">
                                  {packet.protocol}
                                </span>
                              </div>
                              <div className="text-gray-300 text-xs">
                                {packet.sourcePort}
                              </div>
                              <div className="text-gray-300 text-xs">
                                {packet.destinationPort}
                              </div>
                              <div className="text-gray-300 text-xs">
                                {packet.size}B
                              </div>
                              <div className="text-xs">
                                {packet.threat ? (
                                  <span className="text-red-400">
                                    ⚠ {packet.threatType}
                                  </span>
                                ) : (
                                  <span className="text-green-400">
                                    ✓ Clean
                                  </span>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Pagination */}
                  <div className="p-4 border-t border-gray-700 flex justify-between items-center">
                    <div className="flex items-center gap-4">
                      <select
                        value={packetsPerPage}
                        onChange={(e) =>
                          setPacketsPerPage(parseInt(e.target.value))
                        }
                        className="px-3 py-1 bg-slate-700 border border-gray-600 rounded text-white text-sm"
                      >
                        <option value={25}>25 per page</option>
                        <option value={50}>50 per page</option>
                        <option value={100}>100 per page</option>
                      </select>
                      <span className="text-gray-400 text-sm">
                        Showing {(currentPage - 1) * packetsPerPage + 1} to{" "}
                        {Math.min(
                          currentPage * packetsPerPage,
                          filteredPackets.length,
                        )}{" "}
                        of {filteredPackets.length} packets
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() =>
                          setCurrentPage(Math.max(1, currentPage - 1))
                        }
                        disabled={currentPage === 1}
                        className="px-3 py-1 bg-slate-700 border border-gray-600 rounded text-white disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        Previous
                      </button>
                      <span className="text-gray-400 text-sm px-3">
                        Page {currentPage} of {totalPages}
                      </span>
                      <button
                        onClick={() =>
                          setCurrentPage(Math.min(totalPages, currentPage + 1))
                        }
                        disabled={currentPage === totalPages}
                        className="px-3 py-1 bg-slate-700 border border-gray-600 rounded text-white disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        Next
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* Sidebar */}
              <div className="space-y-6">
                {/* Export Controls */}
                <div className="glass-effect rounded-xl p-6">
                  <h3 className="text-lg font-bold text-white mb-4">
                    Export Data
                  </h3>
                  <div className="space-y-4">
                    <select
                      value={exportFormat}
                      onChange={(e) => setExportFormat(e.target.value)}
                      className="w-full px-3 py-2 bg-slate-700 border border-gray-600 rounded-lg text-white"
                    >
                      <option value="json">JSON Format</option>
                      <option value="csv">CSV Format</option>
                      <option value="pcap">PCAP Format</option>
                    </select>
                    <button
                      onClick={exportPackets}
                      disabled={isLoading || filteredPackets.length === 0}
                      className="w-full btn-primary py-2 disabled:opacity-50"
                    >
                      {isLoading ? "Exporting..." : "Export Packets"}
                    </button>
                  </div>
                </div>

                {/* Quick Stats */}
                <div className="glass-effect rounded-xl p-6">
                  <h3 className="text-lg font-bold text-white mb-4">
                    Protocol Distribution
                  </h3>
                  <div className="space-y-2">
                    {Object.entries(stats.protocolStats)
                      .sort(([, a], [, b]) => b - a)
                      .slice(0, 5)
                      .map(([protocol, count]) => (
                        <div
                          key={protocol}
                          className="flex justify-between items-center"
                        >
                          <span className="text-gray-300 uppercase">
                            {protocol}
                          </span>
                          <span className="text-blue-400">{count}</span>
                        </div>
                      ))}
                  </div>
                </div>

                {/* Top Talkers */}
                <div className="glass-effect rounded-xl p-6">
                  <h3 className="text-lg font-bold text-white mb-4">
                    Top Talkers
                  </h3>
                  <div className="space-y-2">
                    {Object.entries(stats.topTalkers)
                      .sort(([, a], [, b]) => b - a)
                      .slice(0, 5)
                      .map(([ip, count]) => (
                        <div
                          key={ip}
                          className="flex justify-between items-center"
                        >
                          <span className="text-gray-300 font-mono text-sm">
                            {ip}
                          </span>
                          <span className="text-green-400">{count}</span>
                        </div>
                      ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Packet Details Panel */}
          {selectedPacket && (
            <div className="mt-6 glass-effect rounded-xl p-6">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-xl font-bold text-white">Packet Details</h3>
                <button
                  onClick={() => setSelectedPacket(null)}
                  className="text-gray-400 hover:text-white"
                >
                  <svg
                    className="w-6 h-6"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M6 18L18 6M6 6l12 12"
                    />
                  </svg>
                </button>
              </div>

              <div className="grid md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-lg font-semibold text-white mb-3">
                    Basic Information
                  </h4>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Timestamp:</span>
                      <span className="text-gray-300">
                        {new Date(selectedPacket.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Source IP:</span>
                      <span className="text-gray-300 font-mono">
                        {selectedPacket.sourceIp}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Destination IP:</span>
                      <span className="text-gray-300 font-mono">
                        {selectedPacket.destinationIp}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Protocol:</span>
                      <span className="text-blue-400 uppercase">
                        {selectedPacket.protocol}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Source Port:</span>
                      <span className="text-gray-300">
                        {selectedPacket.sourcePort}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Destination Port:</span>
                      <span className="text-gray-300">
                        {selectedPacket.destinationPort}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Size:</span>
                      <span className="text-gray-300">
                        {selectedPacket.size} bytes
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">TTL:</span>
                      <span className="text-gray-300">
                        {selectedPacket.details.ttl}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Checksum:</span>
                      <span className="text-gray-300 font-mono">
                        {selectedPacket.details.checksum}
                      </span>
                    </div>
                  </div>
                </div>

                <div>
                  <h4 className="text-lg font-semibold text-white mb-3">
                    Headers & Payload
                  </h4>
                  <div className="bg-slate-800/50 rounded-lg p-4 h-64 overflow-y-auto scrollbar-thin">
                    <div className="text-sm space-y-3">
                      <div>
                        <div className="text-blue-400 font-medium mb-1">
                          Ethernet Header:
                        </div>
                        <div className="text-gray-300 font-mono text-xs ml-2">
                          <div>
                            Source:{" "}
                            {selectedPacket.details.headers.ethernet.source}
                          </div>
                          <div>
                            Destination:{" "}
                            {
                              selectedPacket.details.headers.ethernet
                                .destination
                            }
                          </div>
                          <div>
                            Type: {selectedPacket.details.headers.ethernet.type}
                          </div>
                        </div>
                      </div>

                      <div>
                        <div className="text-blue-400 font-medium mb-1">
                          IP Header:
                        </div>
                        <div className="text-gray-300 font-mono text-xs ml-2">
                          <div>
                            Version: {selectedPacket.details.headers.ip.version}
                          </div>
                          <div>
                            Header Length:{" "}
                            {selectedPacket.details.headers.ip.headerLength}
                          </div>
                          <div>
                            Type of Service:{" "}
                            {selectedPacket.details.headers.ip.typeOfService}
                          </div>
                          <div>
                            Identification:{" "}
                            {selectedPacket.details.headers.ip.identification}
                          </div>
                        </div>
                      </div>

                      <div>
                        <div className="text-blue-400 font-medium mb-1">
                          Protocol Header:
                        </div>
                        <div className="text-gray-300 font-mono text-xs ml-2">
                          {selectedPacket.details.flags && (
                            <div>Flags: {selectedPacket.details.flags}</div>
                          )}
                          <div>
                            Sequence:{" "}
                            {
                              selectedPacket.details.headers[
                                selectedPacket.protocol
                              ]?.sequenceNumber
                            }
                          </div>
                          <div>
                            Acknowledgment:{" "}
                            {
                              selectedPacket.details.headers[
                                selectedPacket.protocol
                              ]?.acknowledgmentNumber
                            }
                          </div>
                        </div>
                      </div>

                      <div>
                        <div className="text-blue-400 font-medium mb-1">
                          Payload:
                        </div>
                        <div className="text-gray-300 font-mono text-xs ml-2 break-all">
                          {selectedPacket.details.payload}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Analysis Tab */}
          {activeTab === "analysis" && (
            <div className="space-y-6">
              <div className="grid md:grid-cols-2 gap-6">
                <div className="glass-effect rounded-xl p-6">
                  <h3 className="text-xl font-bold text-white mb-4">
                    Traffic Analysis
                  </h3>
                  <div className="text-center text-gray-400">
                    <svg
                      className="w-16 h-16 mx-auto mb-4 opacity-50"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
                      />
                    </svg>
                    <p>Traffic visualization charts will be implemented here</p>
                  </div>
                </div>

                <div className="glass-effect rounded-xl p-6">
                  <h3 className="text-xl font-bold text-white mb-4">
                    Geolocation
                  </h3>
                  <div className="text-center text-gray-400">
                    <svg
                      className="w-16 h-16 mx-auto mb-4 opacity-50"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                      />
                    </svg>
                    <p>Geographic analysis of traffic sources</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Security Alerts Tab */}
          {activeTab === "alerts" && (
            <div className="glass-effect rounded-xl p-6">
              <h3 className="text-xl font-bold text-white mb-6">
                Security Alerts
              </h3>
              <div className="h-96 overflow-y-auto scrollbar-thin scrollbar-thumb-gray-600">
                {alerts.length === 0 ? (
                  <div className="flex items-center justify-center h-full text-gray-400">
                    <div className="text-center">
                      <svg
                        className="w-16 h-16 mx-auto mb-4 opacity-50"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                        />
                      </svg>
                      <p>No security alerts</p>
                      <p className="text-sm text-gray-500 mt-1">
                        Alerts will appear here when threats are detected
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {alerts.map((alert) => (
                      <div
                        key={alert.id}
                        className="bg-slate-800/50 rounded-lg p-4 border-l-4 border-red-500"
                      >
                        <div className="flex justify-between items-start mb-2">
                          <h4 className="font-semibold text-white">
                            {alert.type}
                          </h4>
                          <span
                            className={`text-xs px-2 py-1 rounded ${
                              alert.severity === "Critical"
                                ? "bg-red-600 text-white"
                                : alert.severity === "High"
                                  ? "bg-orange-600 text-white"
                                  : alert.severity === "Medium"
                                    ? "bg-yellow-600 text-black"
                                    : "bg-blue-600 text-white"
                            }`}
                          >
                            {alert.severity}
                          </span>
                        </div>
                        <p className="text-gray-400 text-sm mb-2">
                          {alert.source} → {alert.target}
                        </p>
                        <p className="text-gray-500 text-xs">
                          {alert.timestamp}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
