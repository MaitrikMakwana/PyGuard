import { useState } from "react";
import Navigation from "../components/Navigation";

const Features = () => {
  const [activeTab, setActiveTab] = useState("detection");

  const coreFeatures = [
    {
      icon: (
        <svg
          className="w-12 h-12"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M13 10V3L4 14h7v7l9-11h-7z"
          />
        </svg>
      ),
      title: "Real-Time Packet Capture",
      description:
        "Continuously monitors network traffic with zero-latency processing and intelligent filtering.",
      features: [
        "High-speed packet processing (10Gbps+)",
        "Intelligent traffic filtering",
        "Protocol-aware analysis",
        "Memory-efficient buffering",
        "Live traffic visualization",
      ],
      image:
        "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=600&h=400&fit=crop",
    },
    {
      icon: (
        <svg
          className="w-12 h-12"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"
          />
        </svg>
      ),
      title: "Deep Protocol Inspection",
      description:
        "Advanced analysis of network protocols with multi-layer inspection capabilities.",
      features: [
        "OSI Layer 2-7 analysis",
        "Custom protocol support",
        "Header field extraction",
        "Payload content analysis",
        "Protocol anomaly detection",
      ],
      image:
        "https://images.unsplash.com/photo-1518709268805-4e9042af2176?w=600&h=400&fit=crop",
    },
    {
      icon: (
        <svg
          className="w-12 h-12"
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
      ),
      title: "ML-Powered Detection",
      description:
        "Artificial intelligence algorithms that learn and adapt to identify new threats automatically.",
      features: [
        "Behavioral anomaly detection",
        "Pattern recognition algorithms",
        "Adaptive threat models",
        "False positive reduction",
        "Continuous learning system",
      ],
      image:
        "https://images.unsplash.com/photo-1555949963-aa79dcee981c?w=600&h=400&fit=crop",
    },
    {
      icon: (
        <svg
          className="w-12 h-12"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"
          />
        </svg>
      ),
      title: "Advanced Logging",
      description:
        "Comprehensive data logging with intelligent storage and powerful search capabilities.",
      features: [
        "JSON-structured logging",
        "Real-time indexing",
        "Advanced search queries",
        "Data compression",
        "Long-term retention",
      ],
      image:
        "https://images.unsplash.com/photo-1460925895917-afdab827c52f?w=600&h=400&fit=crop",
    },
  ];

  const detectionCapabilities = [
    {
      category: "Network Attacks",
      threats: [
        "DDoS attacks",
        "Port scanning",
        "Network reconnaissance",
        "ARP spoofing",
        "DNS poisoning",
      ],
      color: "border-red-500",
      bgColor: "bg-red-900/20",
    },
    {
      category: "Application Attacks",
      threats: [
        "SQL injection",
        "Cross-site scripting (XSS)",
        "Command injection",
        "Buffer overflow",
        "Web application attacks",
      ],
      color: "border-orange-500",
      bgColor: "bg-orange-900/20",
    },
    {
      category: "Malware & Intrusions",
      threats: [
        "Malware communication",
        "C&C server connections",
        "Data exfiltration",
        "Lateral movement",
        "Privilege escalation",
      ],
      color: "border-yellow-500",
      bgColor: "bg-yellow-900/20",
    },
    {
      category: "Behavioral Anomalies",
      threats: [
        "Unusual traffic patterns",
        "Off-hours activity",
        "Abnormal data volumes",
        "Suspicious user behavior",
        "Protocol violations",
      ],
      color: "border-blue-500",
      bgColor: "bg-blue-900/20",
    },
  ];

  const dashboardFeatures = [
    {
      title: "Real-Time Monitoring",
      description: "Live network traffic visualization with interactive charts",
      image:
        "https://images.unsplash.com/photo-1551288049-bebda4e38f71?w=600&h=400&fit=crop",
    },
    {
      title: "Threat Alerts",
      description: "Instant notifications with severity classification",
      image:
        "https://images.unsplash.com/photo-1563206767-5b18f218e8de?w=600&h=400&fit=crop",
    },
    {
      title: "Analytics Dashboard",
      description: "Comprehensive security metrics and trend analysis",
      image:
        "https://images.unsplash.com/photo-1666875753105-c63a6f3bdc86?w=600&h=400&fit=crop",
    },
  ];

  const integrations = [
    {
      name: "SIEM Integration",
      logo: "🔧",
      description: "Seamless integration with popular SIEM platforms",
    },
    {
      name: "Slack Notifications",
      logo: "📱",
      description: "Real-time alerts sent to your team channels",
    },
    {
      name: "REST API",
      logo: "🔌",
      description: "Full API access for custom integrations",
    },
    {
      name: "Webhook Support",
      logo: "🔗",
      description: "Custom webhook endpoints for automated responses",
    },
    {
      name: "Email Alerts",
      logo: "📧",
      description: "Configurable email notifications and reports",
    },
    {
      name: "Export Tools",
      logo: "📊",
      description: "Export data to CSV, JSON, and PCAP formats",
    },
  ];

  const tabContent = {
    detection: {
      title: "Threat Detection Engine",
      content: (
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
          {detectionCapabilities.map((category, index) => (
            <div
              key={index}
              className={`glass-effect rounded-xl p-6 border-l-4 ${category.color} ${category.bgColor}`}
            >
              <h4 className="text-lg font-semibold text-white mb-4">
                {category.category}
              </h4>
              <ul className="space-y-2">
                {category.threats.map((threat, idx) => (
                  <li
                    key={idx}
                    className="text-gray-300 text-sm flex items-center"
                  >
                    <span className="w-2 h-2 bg-blue-400 rounded-full mr-2"></span>
                    {threat}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      ),
    },
    dashboard: {
      title: "Interactive Dashboard",
      content: (
        <div className="grid md:grid-cols-3 gap-8">
          {dashboardFeatures.map((feature, index) => (
            <div
              key={index}
              className="glass-effect rounded-xl overflow-hidden"
            >
              <img
                src={feature.image}
                alt={feature.title}
                className="w-full h-48 object-cover"
              />
              <div className="p-6">
                <h4 className="text-xl font-semibold text-white mb-3">
                  {feature.title}
                </h4>
                <p className="text-gray-300">{feature.description}</p>
              </div>
            </div>
          ))}
        </div>
      ),
    },
    integrations: {
      title: "Integrations & APIs",
      content: (
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {integrations.map((integration, index) => (
            <div
              key={index}
              className="glass-effect rounded-xl p-6 hover:cyber-glow transition-all duration-300"
            >
              <div className="text-4xl mb-4">{integration.logo}</div>
              <h4 className="text-lg font-semibold text-white mb-2">
                {integration.name}
              </h4>
              <p className="text-gray-300 text-sm">{integration.description}</p>
            </div>
          ))}
        </div>
      ),
    },
  };

  return (
    <div className="min-h-screen bg-slate-900">
      <Navigation />

      {/* Hero Section */}
      <section className="pt-20 section-padding bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
        <div className="container-custom">
          <div className="text-center max-w-4xl mx-auto">
            <h1 className="text-5xl md:text-6xl font-bold text-white mb-6">
              Powerful <span className="gradient-text">Features</span>
            </h1>
            <p className="text-xl text-gray-300 mb-8 leading-relaxed">
              Discover PyGuard Pro's comprehensive suite of cybersecurity
              features designed to protect your network infrastructure with
              advanced AI-powered threat detection.
            </p>
            <button
              className="btn-primary text-lg px-8 py-4"
              onClick={() => (window.location.href = "/dashboard")}
            >
              Try Interactive Demo
            </button>
          </div>
        </div>
      </section>

      {/* Core Features */}
      <section className="section-padding">
        <div className="container-custom">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-white mb-6">
              Core Security Features
            </h2>
            <p className="text-xl text-gray-300 max-w-3xl mx-auto">
              Built on cutting-edge technology, PyGuard Pro delivers
              enterprise-grade security capabilities that adapt to evolving
              threats.
            </p>
          </div>

          <div className="space-y-16">
            {coreFeatures.map((feature, index) => (
              <div
                key={index}
                className={`grid lg:grid-cols-2 gap-12 items-center ${
                  index % 2 === 1 ? "lg:grid-flow-dense" : ""
                }`}
              >
                <div className={index % 2 === 1 ? "lg:col-start-2" : ""}>
                  <div className="text-blue-400 mb-6">{feature.icon}</div>
                  <h3 className="text-3xl font-bold text-white mb-4">
                    {feature.title}
                  </h3>
                  <p className="text-xl text-gray-300 mb-6 leading-relaxed">
                    {feature.description}
                  </p>
                  <ul className="space-y-3">
                    {feature.features.map((item, idx) => (
                      <li key={idx} className="flex items-center text-gray-300">
                        <svg
                          className="w-5 h-5 text-green-400 mr-3 flex-shrink-0"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M5 13l4 4L19 7"
                          />
                        </svg>
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
                <div className={index % 2 === 1 ? "lg:col-start-1" : ""}>
                  <div className="glass-effect rounded-2xl p-8 cyber-glow">
                    <img
                      src={feature.image}
                      alt={feature.title}
                      className="w-full h-64 object-cover rounded-lg"
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Feature Tabs */}
      <section className="section-padding bg-slate-800/50">
        <div className="container-custom">
          <div className="text-center mb-12">
            <h2 className="text-4xl font-bold text-white mb-6">
              Explore Advanced Capabilities
            </h2>
          </div>

          {/* Tab Navigation */}
          <div className="flex flex-wrap justify-center gap-4 mb-12">
            {Object.entries(tabContent).map(([key, tab]) => (
              <button
                key={key}
                onClick={() => setActiveTab(key)}
                className={`px-6 py-3 rounded-lg font-medium transition-all duration-300 ${
                  activeTab === key
                    ? "bg-blue-600 text-white shadow-lg"
                    : "bg-slate-700/50 text-gray-300 hover:bg-slate-700"
                }`}
              >
                {tab.title}
              </button>
            ))}
          </div>

          {/* Tab Content */}
          <div className="glass-effect rounded-2xl p-8">
            <h3 className="text-2xl font-bold text-white mb-8 text-center">
              {tabContent[activeTab].title}
            </h3>
            {tabContent[activeTab].content}
          </div>
        </div>
      </section>

      {/* Performance Stats */}
      <section className="section-padding">
        <div className="container-custom">
          <div className="glass-effect rounded-2xl p-12 cyber-glow">
            <div className="text-center mb-12">
              <h2 className="text-4xl font-bold text-white mb-6">
                Performance Metrics
              </h2>
              <p className="text-xl text-gray-300">
                Real-world performance data from our global network
              </p>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
              <div className="text-center">
                <div className="text-4xl md:text-5xl font-bold gradient-text mb-2">
                  99.9%
                </div>
                <div className="text-gray-300">Accuracy Rate</div>
              </div>
              <div className="text-center">
                <div className="text-4xl md:text-5xl font-bold gradient-text mb-2">
                  &lt;1ms
                </div>
                <div className="text-gray-300">Response Time</div>
              </div>
              <div className="text-center">
                <div className="text-4xl md:text-5xl font-bold gradient-text mb-2">
                  10Gbps+
                </div>
                <div className="text-gray-300">Throughput</div>
              </div>
              <div className="text-center">
                <div className="text-4xl md:text-5xl font-bold gradient-text mb-2">
                  0.01%
                </div>
                <div className="text-gray-300">False Positives</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="section-padding bg-slate-800/50">
        <div className="container-custom">
          <div className="text-center">
            <h2 className="text-4xl font-bold text-white mb-6">
              Ready to Experience These Features?
            </h2>
            <p className="text-xl text-gray-300 mb-8 max-w-2xl mx-auto">
              Start monitoring your network with PyGuard Pro's advanced security
              features. No installation required - run directly in your browser.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <button
                className="btn-primary text-lg px-8 py-4"
                onClick={() => (window.location.href = "/dashboard")}
              >
                Launch Dashboard
              </button>
              <button
                className="btn-secondary text-lg px-8 py-4"
                onClick={() => (window.location.href = "/contact")}
              >
                Contact Sales
              </button>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default Features;
