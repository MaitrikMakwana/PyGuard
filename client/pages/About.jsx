import Navigation from "../components/Navigation";

const About = () => {
  const team = [
    {
      name: "Dr. Sarah Chen",
      role: "CEO & Founder",
      image:
        "https://images.unsplash.com/photo-1494790108755-2616b612e29b?w=300&h=300&fit=crop&crop=face",
      bio: "15+ years in cybersecurity research. Former CISO at Fortune 500 companies. PhD in Computer Science from MIT.",
      linkedin: "#",
    },
    {
      name: "Marcus Rodriguez",
      role: "CTO & Co-Founder",
      image:
        "https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?w=300&h=300&fit=crop&crop=face",
      bio: "Expert in machine learning and network security. Former senior engineer at Google. MS in Cybersecurity from Stanford.",
      linkedin: "#",
    },
    {
      name: "Dr. Aisha Patel",
      role: "Head of AI Research",
      image:
        "https://images.unsplash.com/photo-1580489944761-15a19d654956?w=300&h=300&fit=crop&crop=face",
      bio: "AI researcher specializing in anomaly detection. 50+ published papers. PhD in Machine Learning from Carnegie Mellon.",
      linkedin: "#",
    },
    {
      name: "James Thompson",
      role: "VP of Engineering",
      image:
        "https://images.unsplash.com/photo-1519244703995-f4e0f30006d5?w=300&h=300&fit=crop&crop=face",
      bio: "Software architect with expertise in distributed systems. Former lead engineer at Amazon. 12+ years in tech.",
      linkedin: "#",
    },
  ];

  const timeline = [
    {
      year: "2019",
      title: "Company Founded",
      description:
        "PyGuard was founded with a mission to democratize enterprise-grade cybersecurity using AI.",
    },
    {
      year: "2020",
      title: "First Product Launch",
      description:
        "Released PyGuard Pro v1.0 with basic intrusion detection capabilities.",
    },
    {
      year: "2021",
      title: "AI Integration",
      description:
        "Integrated advanced machine learning algorithms for real-time threat detection.",
    },
    {
      year: "2022",
      title: "Enterprise Adoption",
      description:
        "Reached 100+ enterprise clients and achieved SOC 2 Type II compliance.",
    },
    {
      year: "2023",
      title: "Cloud Platform",
      description:
        "Launched cloud-native platform with global threat intelligence.",
    },
    {
      year: "2024",
      title: "Open Source Initiative",
      description:
        "Made PyGuard Pro free and open-source to benefit the global cybersecurity community.",
    },
  ];

  const values = [
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
            d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
          />
        </svg>
      ),
      title: "Security First",
      description:
        "Every decision we make is guided by our commitment to protecting our users' digital assets.",
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
            d="M13 10V3L4 14h7v7l9-11h-7z"
          />
        </svg>
      ),
      title: "Innovation",
      description:
        "We continuously push the boundaries of what's possible in cybersecurity technology.",
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
            d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"
          />
        </svg>
      ),
      title: "Community",
      description:
        "We believe in open collaboration and sharing knowledge to strengthen global cybersecurity.",
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
            d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
      ),
      title: "Accessibility",
      description:
        "Advanced cybersecurity should be accessible to organizations of all sizes, not just large enterprises.",
    },
  ];

  return (
    <div className="min-h-screen bg-slate-900">
      <Navigation />

      {/* Hero Section */}
      <section className="pt-20 section-padding bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
        <div className="container-custom">
          <div className="text-center max-w-4xl mx-auto">
            <h1 className="text-5xl md:text-6xl font-bold text-white mb-6">
              About <span className="gradient-text">PyGuard Pro</span>
            </h1>
            <p className="text-xl text-gray-300 mb-8 leading-relaxed">
              We're on a mission to make enterprise-grade cybersecurity
              accessible to everyone. Founded by security experts, driven by
              innovation, and committed to protecting the digital world.
            </p>
          </div>
        </div>
      </section>

      {/* Mission & Vision */}
      <section className="section-padding">
        <div className="container-custom">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-4xl font-bold text-white mb-6">
                Our Mission
              </h2>
              <p className="text-xl text-gray-300 mb-6 leading-relaxed">
                To democratize cybersecurity by providing free, open-source,
                AI-powered intrusion detection systems that protect
                organizations of all sizes from evolving cyber threats.
              </p>
              <p className="text-gray-400 leading-relaxed">
                We believe that advanced cybersecurity shouldn't be a privilege
                reserved for large enterprises. Every organization, regardless
                of size or budget, deserves access to cutting-edge threat
                detection and prevention technologies.
              </p>
            </div>
            <div className="glass-effect rounded-2xl p-8 cyber-glow">
              <h3 className="text-2xl font-bold text-white mb-4">Our Vision</h3>
              <p className="text-gray-300 leading-relaxed">
                A world where every network is protected by intelligent,
                adaptive security systems that can predict, detect, and prevent
                cyber attacks before they cause damage. We envision a future
                where cybersecurity is proactive, not reactive.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Company Timeline */}
      <section className="section-padding bg-slate-800/50">
        <div className="container-custom">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-white mb-6">Our Journey</h2>
            <p className="text-xl text-gray-300 max-w-3xl mx-auto">
              From a small startup to a global cybersecurity leader, here's how
              we've evolved to serve the community better.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
            {timeline.map((milestone, index) => (
              <div
                key={index}
                className="glass-effect rounded-xl p-6 hover:cyber-glow transition-all duration-300"
              >
                <div className="text-3xl font-bold gradient-text mb-4">
                  {milestone.year}
                </div>
                <h3 className="text-xl font-semibold text-white mb-3">
                  {milestone.title}
                </h3>
                <p className="text-gray-300 leading-relaxed">
                  {milestone.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Core Values */}
      <section className="section-padding">
        <div className="container-custom">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-white mb-6">Our Values</h2>
            <p className="text-xl text-gray-300 max-w-3xl mx-auto">
              These principles guide everything we do, from product development
              to customer service and community engagement.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8">
            {values.map((value, index) => (
              <div key={index} className="text-center">
                <div className="text-blue-400 mb-6 flex justify-center">
                  {value.icon}
                </div>
                <h3 className="text-xl font-semibold text-white mb-4">
                  {value.title}
                </h3>
                <p className="text-gray-300 leading-relaxed">
                  {value.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Team Section */}
      <section className="section-padding bg-slate-800/50">
        <div className="container-custom">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold text-white mb-6">
              Meet Our Team
            </h2>
            <p className="text-xl text-gray-300 max-w-3xl mx-auto">
              Passionate cybersecurity experts, researchers, and engineers
              working together to build a safer digital world.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8">
            {team.map((member, index) => (
              <div key={index} className="text-center group">
                <div className="glass-effect rounded-xl p-6 hover:cyber-glow transition-all duration-300">
                  <img
                    src={member.image}
                    alt={member.name}
                    className="w-24 h-24 rounded-full mx-auto mb-4 object-cover"
                  />
                  <h3 className="text-xl font-semibold text-white mb-2">
                    {member.name}
                  </h3>
                  <p className="text-blue-400 font-medium mb-4">
                    {member.role}
                  </p>
                  <p className="text-gray-300 text-sm leading-relaxed mb-4">
                    {member.bio}
                  </p>
                  <a
                    href={member.linkedin}
                    className="text-blue-400 hover:text-blue-300 transition-colors"
                  >
                    <svg
                      className="w-5 h-5 mx-auto"
                      fill="currentColor"
                      viewBox="0 0 20 20"
                    >
                      <path
                        fillRule="evenodd"
                        d="M16.338 16.338H13.67V12.16c0-.995-.017-2.277-1.387-2.277-1.39 0-1.601 1.086-1.601 2.207v4.248H8.014v-8.59h2.559v1.174h.037c.356-.675 1.227-1.387 2.526-1.387 2.703 0 3.203 1.778 3.203 4.092v4.711zM5.005 6.575a1.548 1.548 0 11-.003-3.096 1.548 1.548 0 01.003 3.096zm-1.337 9.763H6.34v-8.59H3.667v8.59zM17.668 1H2.328C1.595 1 1 1.581 1 2.298v15.403C1 18.418 1.595 19 2.328 19h15.34c.734 0 1.332-.582 1.332-1.299V2.298C19 1.581 18.402 1 17.668 1z"
                        clipRule="evenodd"
                      />
                    </svg>
                  </a>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="section-padding">
        <div className="container-custom">
          <div className="glass-effect rounded-2xl p-12 cyber-glow">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
              <div>
                <div className="text-4xl font-bold gradient-text mb-2">5+</div>
                <div className="text-gray-300">Years of Excellence</div>
              </div>
              <div>
                <div className="text-4xl font-bold gradient-text mb-2">1M+</div>
                <div className="text-gray-300">Networks Protected</div>
              </div>
              <div>
                <div className="text-4xl font-bold gradient-text mb-2">
                  99.9%
                </div>
                <div className="text-gray-300">Threat Detection Rate</div>
              </div>
              <div>
                <div className="text-4xl font-bold gradient-text mb-2">
                  24/7
                </div>
                <div className="text-gray-300">Community Support</div>
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
              Join Our Mission
            </h2>
            <p className="text-xl text-gray-300 mb-8 max-w-2xl mx-auto">
              Whether you're a cybersecurity professional, developer, or
              organization looking to strengthen your security posture, we'd
              love to have you as part of our community.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <button
                className="btn-primary text-lg px-8 py-4"
                onClick={() => (window.location.href = "/dashboard")}
              >
                Start Using PyGuard Pro
              </button>
              <button
                className="btn-secondary text-lg px-8 py-4"
                onClick={() => (window.location.href = "/contact")}
              >
                Get In Touch
              </button>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default About;
