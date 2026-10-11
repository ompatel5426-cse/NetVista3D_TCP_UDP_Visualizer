/**
 * NetVista 3D: Connection-Oriented vs Connectionless Services
 * Course: ITUC201 - Fundamentals of Computer Networks
 * Author: Student 25CS074
 */

(() => {
  // --- Scenarios Configuration ---
  const SCENARIOS = {
    tcp: {
      standard: {
        name: "Complete TCP Lifecycle (Handshake, Data, 4-Way Close)",
        steps: [
          {
            label: "1. Client sends SYN (Connection Request)",
            desc: "Active Open initiated by Client. Proposes Initial Sequence Number (ISN).",
            note: "The client sends a TCP segment with SYN=1, ACK=0, Seq=100. It enters SYN_SENT state. No application payload is transferred during the handshake.",
            type: "pkt-syn",
            direction: "to-receiver",
            route: "r1",
            senderState: "SYN_SENT",
            receiverState: "LISTEN",
            inspector: {
              protocol: "TCP",
              srcPort: "49152",
              dstPort: "80 (HTTP)",
              seqNum: "100",
              ackNum: "0",
              flags: ["SYN"],
              headerLen: "20 Bytes",
              payloadLen: "0 Bytes",
              payload: "None (Handshake SYN)",
              checksum: "0x7A4C (Valid)"
            }
          },
          {
            label: "2. Server replies with SYN-ACK",
            desc: "Server acknowledges client's SYN and synchronizes its own sequence number.",
            note: "The server acknowledges Client ISN (Ack=101) and picks its own ISN (Seq=300). Server transitions from LISTEN to SYN_RCVD state. Half-open connection allocated.",
            type: "pkt-syn-ack",
            direction: "to-sender",
            route: "r1",
            senderState: "SYN_SENT",
            receiverState: "SYN_RCVD",
            inspector: {
              protocol: "TCP",
              srcPort: "80 (HTTP)",
              dstPort: "49152",
              seqNum: "300",
              ackNum: "101 (ISN_c + 1)",
              flags: ["SYN", "ACK"],
              headerLen: "20 Bytes",
              payloadLen: "0 Bytes",
              payload: "None (Handshake SYN-ACK)",
              checksum: "0x3F88 (Valid)"
            }
          },
          {
            label: "3. Client sends ACK (Connection Established)",
            desc: "Three-way handshake complete. Full-duplex connection established.",
            note: "Client acknowledges Server ISN (Ack=301) with Seq=101. Both endpoints now reach ESTABLISHED state. Both ends have verified bidirectional reachability.",
            type: "pkt-ack",
            direction: "to-receiver",
            route: "r1",
            senderState: "ESTABLISHED",
            receiverState: "ESTABLISHED",
            inspector: {
              protocol: "TCP",
              srcPort: "49152",
              dstPort: "80 (HTTP)",
              seqNum: "101",
              ackNum: "301 (ISN_s + 1)",
              flags: ["ACK"],
              headerLen: "20 Bytes",
              payloadLen: "0 Bytes",
              payload: "None (Final Handshake ACK)",
              checksum: "0x6E21 (Valid)"
            }
          },
          {
            label: "4. Client sends HTTP Request Data (100 Bytes)",
            desc: "Client transmits application byte stream over the active connection.",
            note: "Client sends HTTP request 'GET /index.html' (100 bytes) with Seq=101..200. PSH flag pushed. Receiver buffers and delivers stream in order to application.",
            type: "pkt-data",
            direction: "to-receiver",
            route: "r1",
            senderState: "ESTABLISHED",
            receiverState: "ESTABLISHED",
            inspector: {
              protocol: "TCP",
              srcPort: "49152",
              dstPort: "80 (HTTP)",
              seqNum: "101",
              ackNum: "301",
              flags: ["ACK", "PSH"],
              headerLen: "20 Bytes",
              payloadLen: "100 Bytes",
              payload: "GET /index.html HTTP/1.1\\r\\nHost: example.edu...",
              checksum: "0x91DC (Valid)"
            }
          },
          {
            label: "5. Server returns Cumulative ACK + Response Data",
            desc: "Server acknowledges client data and replies with HTTP 200 OK (250 Bytes).",
            note: "Server sends Ack=201 (expecting byte 201 next) along with 250 bytes of response data (Seq=301..550). Demonstrates full-duplex cumulative acknowledgement.",
            type: "pkt-data",
            direction: "to-sender",
            route: "r1",
            senderState: "ESTABLISHED",
            receiverState: "ESTABLISHED",
            inspector: {
              protocol: "TCP",
              srcPort: "80 (HTTP)",
              dstPort: "49152",
              seqNum: "301",
              ackNum: "201",
              flags: ["ACK", "PSH"],
              headerLen: "20 Bytes",
              payloadLen: "250 Bytes",
              payload: "HTTP/1.1 200 OK\\r\\nContent-Type: text/html...",
              checksum: "0x12FE (Valid)"
            }
          },
          {
            label: "6. Client acknowledges Response Data",
            desc: "Client acknowledges all 250 bytes of Server data.",
            note: "Client sends Ack=551 with Seq=201. Both endpoints have successfully completed reliable data exchange. Flow control window updated.",
            type: "pkt-ack",
            direction: "to-receiver",
            route: "r1",
            senderState: "ESTABLISHED",
            receiverState: "ESTABLISHED",
            inspector: {
              protocol: "TCP",
              srcPort: "49152",
              dstPort: "80 (HTTP)",
              seqNum: "201",
              ackNum: "551",
              flags: ["ACK"],
              headerLen: "20 Bytes",
              payloadLen: "0 Bytes",
              payload: "None (Pure ACK for Data)",
              checksum: "0x4B3A (Valid)"
            }
          },
          {
            label: "7. Client initiates Close with FIN",
            desc: "Active close: Client announces it has no more data to transmit.",
            note: "Client sends FIN segment with Seq=201, Ack=551. Client transitions to FIN_WAIT_1. The client can still receive incoming data from server (Half-closed state).",
            type: "pkt-fin",
            direction: "to-receiver",
            route: "r1",
            senderState: "FIN_WAIT_1",
            receiverState: "ESTABLISHED",
            inspector: {
              protocol: "TCP",
              srcPort: "49152",
              dstPort: "80 (HTTP)",
              seqNum: "201",
              ackNum: "551",
              flags: ["FIN", "ACK"],
              headerLen: "20 Bytes",
              payloadLen: "0 Bytes",
              payload: "None (Client FIN)",
              checksum: "0x55FA (Valid)"
            }
          },
          {
            label: "8. Server sends ACK for Client FIN",
            desc: "Passive close: Server acknowledges Client's termination request.",
            note: "Server sends Ack=202. Server enters CLOSE_WAIT state. Client receives this ACK and enters FIN_WAIT_2 state, waiting for Server's own FIN.",
            type: "pkt-ack",
            direction: "to-sender",
            route: "r1",
            senderState: "FIN_WAIT_2",
            receiverState: "CLOSE_WAIT",
            inspector: {
              protocol: "TCP",
              srcPort: "80 (HTTP)",
              dstPort: "49152",
              seqNum: "551",
              ackNum: "202",
              flags: ["ACK"],
              headerLen: "20 Bytes",
              payloadLen: "0 Bytes",
              payload: "None (ACK for Client FIN)",
              checksum: "0x8D12 (Valid)"
            }
          },
          {
            label: "9. Server completes its tasks & sends FIN",
            desc: "Server finishes sending pending data and announces closure.",
            note: "Server sends its own FIN segment with Seq=551, Ack=202. Server enters LAST_ACK state, waiting for the final acknowledgement from Client.",
            type: "pkt-fin",
            direction: "to-sender",
            route: "r1",
            senderState: "FIN_WAIT_2",
            receiverState: "LAST_ACK",
            inspector: {
              protocol: "TCP",
              srcPort: "80 (HTTP)",
              dstPort: "49152",
              seqNum: "551",
              ackNum: "202",
              flags: ["FIN", "ACK"],
              headerLen: "20 Bytes",
              payloadLen: "0 Bytes",
              payload: "None (Server FIN)",
              checksum: "0xA2BC (Valid)"
            }
          },
          {
            label: "10. Client sends final ACK & enters TIME_WAIT",
            desc: "Orderly four-way release concluded. TIME_WAIT ensures graceful closure.",
            note: "Client sends final Ack=552, Seq=202. Server enters CLOSED immediately upon receipt. Client enters TIME_WAIT (2MSL duration) to handle any delayed duplicate packets before finally entering CLOSED.",
            type: "pkt-ack",
            direction: "to-receiver",
            route: "r1",
            senderState: "TIME_WAIT (-> CLOSED)",
            receiverState: "CLOSED",
            inspector: {
              protocol: "TCP",
              srcPort: "49152",
              dstPort: "80 (HTTP)",
              seqNum: "202",
              ackNum: "552",
              flags: ["ACK"],
              headerLen: "20 Bytes",
              payloadLen: "0 Bytes",
              payload: "None (Final Close ACK)",
              checksum: "0x1123 (Valid)"
            }
          }
        ]
      },
      handshake: {
        name: "TCP 3-Way Handshake Deep Dive",
        steps: [
          {
            label: "1. Client SYN (ISN_c = 5000)",
            desc: "Client initiates active open, advertising its initial sequence number.",
            note: "SYN consumes 1 sequence number. Client socket state transitions from CLOSED to SYN_SENT.",
            type: "pkt-syn",
            direction: "to-receiver",
            route: "r1",
            senderState: "SYN_SENT",
            receiverState: "LISTEN",
            inspector: {
              protocol: "TCP",
              srcPort: "51000",
              dstPort: "443 (HTTPS)",
              seqNum: "5000",
              ackNum: "0",
              flags: ["SYN"],
              headerLen: "20 Bytes",
              payloadLen: "0 Bytes",
              payload: "None (SYN packet)",
              checksum: "0xB411 (Valid)"
            }
          },
          {
            label: "2. Server SYN-ACK (ISN_s = 8000, Ack = 5001)",
            desc: "Server acknowledges client sequence and proposes its own.",
            note: "Server validates client SYN and increments client sequence by 1 (Ack = 5001). Server transitions to SYN_RCVD.",
            type: "pkt-syn-ack",
            direction: "to-sender",
            route: "r1",
            senderState: "SYN_SENT",
            receiverState: "SYN_RCVD",
            inspector: {
              protocol: "TCP",
              srcPort: "443 (HTTPS)",
              dstPort: "51000",
              seqNum: "8000",
              ackNum: "5001",
              flags: ["SYN", "ACK"],
              headerLen: "20 Bytes",
              payloadLen: "0 Bytes",
              payload: "None (SYN-ACK packet)",
              checksum: "0x98FF (Valid)"
            }
          },
          {
            label: "3. Client ACK (Seq = 5001, Ack = 8001)",
            desc: "Client confirms server sequence. Handshake complete.",
            note: "Client enters ESTABLISHED. Server enters ESTABLISHED upon arrival. Total delay = 1 RTT.",
            type: "pkt-ack",
            direction: "to-receiver",
            route: "r1",
            senderState: "ESTABLISHED",
            receiverState: "ESTABLISHED",
            inspector: {
              protocol: "TCP",
              srcPort: "51000",
              dstPort: "443 (HTTPS)",
              seqNum: "5001",
              ackNum: "8001",
              flags: ["ACK"],
              headerLen: "20 Bytes",
              payloadLen: "0 Bytes",
              payload: "None (ACK packet)",
              checksum: "0xCC22 (Valid)"
            }
          }
        ]
      },
      retransmit: {
        name: "TCP Packet Loss & Retransmission Recovery",
        steps: [
          {
            label: "1. Connection Established & Data 1 Sent",
            desc: "Client sends Segment 1 (Seq 1001..1100, 100 Bytes).",
            note: "Connection is in ESTABLISHED state. Client sends Segment 1 and starts retransmission timer (RTO).",
            type: "pkt-data",
            direction: "to-receiver",
            route: "r1",
            senderState: "ESTABLISHED",
            receiverState: "ESTABLISHED",
            inspector: {
              protocol: "TCP",
              srcPort: "49152",
              dstPort: "80",
              seqNum: "1001",
              ackNum: "500",
              flags: ["ACK", "PSH"],
              headerLen: "20 Bytes",
              payloadLen: "100 Bytes",
              payload: "Application Payload #1 (100 B)",
              checksum: "0x3456 (Valid)"
            }
          },
          {
            label: "2. Server receives Segment 1 & replies with ACK 1101",
            desc: "Cumulative ACK confirms receipt of all bytes up to 1100.",
            note: "Server sends ACK with Ack=1101. Client cancels timer for Segment 1.",
            type: "pkt-ack",
            direction: "to-sender",
            route: "r1",
            senderState: "ESTABLISHED",
            receiverState: "ESTABLISHED",
            inspector: {
              protocol: "TCP",
              srcPort: "80",
              dstPort: "49152",
              seqNum: "500",
              ackNum: "1101",
              flags: ["ACK"],
              headerLen: "20 Bytes",
              payloadLen: "0 Bytes",
              payload: "None (ACK for Seg 1)",
              checksum: "0x7890 (Valid)"
            }
          },
          {
            label: "3. Client sends Segment 2 (Seq 1101..1200) - Packet Lost!",
            desc: "Segment 2 encounters router buffer overflow and is dropped.",
            note: "Router R1 drops the packet due to congestion. Server never receives Segment 2. Client is waiting for ACK.",
            type: "pkt-dropped",
            direction: "to-receiver",
            route: "r1-drop",
            senderState: "ESTABLISHED",
            receiverState: "ESTABLISHED",
            inspector: {
              protocol: "TCP",
              srcPort: "49152",
              dstPort: "80",
              seqNum: "1101",
              ackNum: "500",
              flags: ["ACK", "PSH"],
              headerLen: "20 Bytes",
              payloadLen: "100 Bytes",
              payload: "Application Payload #2 [DROPPED]",
              checksum: "0xABCD (Valid)"
            }
          },
          {
            label: "4. Retransmission Timeout (RTO) Expires at Client",
            desc: "Client timer elapses with no ACK received.",
            note: "TCP connection-oriented reliability mechanism detects missing ACK via timer expiration. Congestion window adjusted.",
            type: "pkt-data",
            direction: "none",
            route: "none",
            senderState: "ESTABLISHED (Timeout)",
            receiverState: "ESTABLISHED",
            inspector: {
              protocol: "TCP",
              srcPort: "Client Internal",
              dstPort: "Timer Engine",
              seqNum: "N/A",
              ackNum: "N/A",
              flags: ["RTO_TIMEOUT"],
              headerLen: "N/A",
              payloadLen: "N/A",
              payload: "Timer expired: Retransmission triggered",
              checksum: "N/A"
            }
          },
          {
            label: "5. Client Retransmits Segment 2 (Seq 1101..1200)",
            desc: "Identical segment resent automatically by transport layer.",
            note: "Client re-sends bytes 1101..1200 with identical sequence number. No application layer intervention required.",
            type: "pkt-data",
            direction: "to-receiver",
            route: "r1",
            senderState: "ESTABLISHED",
            receiverState: "ESTABLISHED",
            inspector: {
              protocol: "TCP",
              srcPort: "49152",
              dstPort: "80",
              seqNum: "1101",
              ackNum: "500",
              flags: ["ACK", "PSH"],
              headerLen: "20 Bytes",
              payloadLen: "100 Bytes",
              payload: "Application Payload #2 (Retransmission)",
              checksum: "0xABCD (Valid)"
            }
          },
          {
            label: "6. Server receives Segment 2 & returns ACK 1201",
            desc: "Server successfully buffers Segment 2 and acknowledges.",
            note: "Reliable, lossless in-order stream delivery is restored completely. Byte-stream integrity guaranteed.",
            type: "pkt-ack",
            direction: "to-sender",
            route: "r1",
            senderState: "ESTABLISHED",
            receiverState: "ESTABLISHED",
            inspector: {
              protocol: "TCP",
              srcPort: "80",
              dstPort: "49152",
              seqNum: "500",
              ackNum: "1201",
              flags: ["ACK"],
              headerLen: "20 Bytes",
              payloadLen: "0 Bytes",
              payload: "None (ACK for Retransmitted Seg 2)",
              checksum: "0xEF01 (Valid)"
            }
          }
        ]
      }
    },
    udp: {
      standard: {
        name: "Independent Datagram Streaming (Multi-path)",
        steps: [
          {
            label: "1. Sender sends Datagram 1 via Router R1",
            desc: "Immediate transmission with 0 RTT connection setup overhead.",
            note: "UDP is connectionless. Sender emits Datagram 1 without handshake. Router R1 forwards it along primary path.",
            type: "pkt-udp",
            direction: "to-receiver",
            route: "r1",
            senderState: "STATELESS (Ready)",
            receiverState: "STATELESS (Ready)",
            inspector: {
              protocol: "UDP",
              srcPort: "53211",
              dstPort: "5004 (RTP Audio)",
              seqNum: "N/A (No Seq Num)",
              ackNum: "N/A (No ACK)",
              flags: ["NONE (No TCP Flags)"],
              headerLen: "8 Bytes (Fixed)",
              payloadLen: "120 Bytes",
              payload: "Voice Packet #1 [Timestamp: 0ms]",
              checksum: "0x4F12 (Optional Checksum)"
            }
          },
          {
            label: "2. Sender sends Datagram 2 via Router R2",
            desc: "Datagram 2 routed independently along an alternate network link.",
            note: "Each datagram carries complete destination addressing. Intermediate routing decisions are independent; R2 has longer delay.",
            type: "pkt-udp",
            direction: "to-receiver",
            route: "r2",
            senderState: "STATELESS (Ready)",
            receiverState: "STATELESS (Ready)",
            inspector: {
              protocol: "UDP",
              srcPort: "53211",
              dstPort: "5004 (RTP Audio)",
              seqNum: "N/A",
              ackNum: "N/A",
              flags: ["NONE"],
              headerLen: "8 Bytes (Fixed)",
              payloadLen: "120 Bytes",
              payload: "Voice Packet #2 [Timestamp: 20ms]",
              checksum: "0x88A1 (Valid)"
            }
          },
          {
            label: "3. Sender sends Datagram 3 via Router R1",
            desc: "Datagram 3 sent immediately over the faster R1 path.",
            note: "Datagram 3 travels via low-latency Router R1 while Datagram 2 is still traversing high-latency Router R2.",
            type: "pkt-udp",
            direction: "to-receiver",
            route: "r1",
            senderState: "STATELESS (Ready)",
            receiverState: "STATELESS (Ready)",
            inspector: {
              protocol: "UDP",
              srcPort: "53211",
              dstPort: "5004 (RTP Audio)",
              seqNum: "N/A",
              ackNum: "N/A",
              flags: ["NONE"],
              headerLen: "8 Bytes (Fixed)",
              payloadLen: "120 Bytes",
              payload: "Voice Packet #3 [Timestamp: 40ms]",
              checksum: "0x2D90 (Valid)"
            }
          },
          {
            label: "4. Receiver receives Datagram 1 & Datagram 3 (Out of Order!)",
            desc: "Datagram 3 arrives BEFORE Datagram 2 due to independent paths.",
            note: "UDP does not reorder or buffer datagrams. It immediately passes Datagram 3 to the application layer. The application must handle ordering.",
            type: "pkt-udp",
            direction: "to-receiver",
            route: "r1",
            senderState: "STATELESS",
            receiverState: "STATELESS",
            inspector: {
              protocol: "UDP",
              srcPort: "53211",
              dstPort: "5004 (RTP Audio)",
              seqNum: "N/A",
              ackNum: "N/A",
              flags: ["NONE"],
              headerLen: "8 Bytes",
              payloadLen: "120 Bytes",
              payload: "Voice Packet #3 delivered before #2!",
              checksum: "0x2D90 (Valid)"
            }
          },
          {
            label: "5. Receiver receives Datagram 2 (Delayed Arrival)",
            desc: "Datagram 2 finally arrives via Router R2.",
            note: "Transport layer does not keep track of missing packets. It delivers Datagram 2 upon arrival with zero connection state overhead.",
            type: "pkt-udp",
            direction: "to-receiver",
            route: "r2",
            senderState: "STATELESS",
            receiverState: "STATELESS",
            inspector: {
              protocol: "UDP",
              srcPort: "53211",
              dstPort: "5004 (RTP Audio)",
              seqNum: "N/A",
              ackNum: "N/A",
              flags: ["NONE"],
              headerLen: "8 Bytes",
              payloadLen: "120 Bytes",
              payload: "Voice Packet #2 (Arrived late)",
              checksum: "0x88A1 (Valid)"
            }
          }
        ]
      },
      loss: {
        name: "Datagram Loss & Lack of Retransmission",
        steps: [
          {
            label: "1. Client sends DNS Query Datagram (Port 53)",
            desc: "Single datagram query sent without prior connection setup.",
            note: "DNS Client sends a 36-byte query for 'example.edu' directly to 203.0.113.50:53. Minimal overhead.",
            type: "pkt-udp",
            direction: "to-receiver",
            route: "r1",
            senderState: "STATELESS",
            receiverState: "STATELESS",
            inspector: {
              protocol: "UDP",
              srcPort: "60124",
              dstPort: "53 (DNS)",
              seqNum: "N/A",
              ackNum: "N/A",
              flags: ["NONE"],
              headerLen: "8 Bytes",
              payloadLen: "36 Bytes",
              payload: "DNS Query: IN A example.edu",
              checksum: "0x6A19 (Valid)"
            }
          },
          {
            label: "2. Server sends DNS Response Datagram",
            desc: "DNS Server responds immediately to the sender's IP and port.",
            note: "Server answers with IP address 93.184.216.34 in a single reply datagram. Round trip complete in 1 RTT.",
            type: "pkt-udp",
            direction: "to-sender",
            route: "r1",
            senderState: "STATELESS",
            receiverState: "STATELESS",
            inspector: {
              protocol: "UDP",
              srcPort: "53 (DNS)",
              dstPort: "60124",
              seqNum: "N/A",
              ackNum: "N/A",
              flags: ["NONE"],
              headerLen: "8 Bytes",
              payloadLen: "52 Bytes",
              payload: "DNS Answer: 93.184.216.34 (TTL 300)",
              checksum: "0x98FE (Valid)"
            }
          },
          {
            label: "3. Client sends 2nd Query - Dropped at Router R2",
            desc: "Datagram dropped due to intermediate router queue discard.",
            note: "Intermediate network router drops the packet. In UDP, there is no transport-layer notification, ACK, or retransmission.",
            type: "pkt-dropped",
            direction: "to-receiver",
            route: "r2-drop",
            senderState: "STATELESS",
            receiverState: "STATELESS",
            inspector: {
              protocol: "UDP",
              srcPort: "60125",
              dstPort: "53 (DNS)",
              seqNum: "N/A",
              ackNum: "N/A",
              flags: ["NONE"],
              headerLen: "8 Bytes",
              payloadLen: "36 Bytes",
              payload: "DNS Query: IN A college.edu [DROPPED]",
              checksum: "0x44B1 (Valid)"
            }
          },
          {
            label: "4. No Transport Retransmission Occurs",
            desc: "UDP transport layer takes no recovery action whatsoever.",
            note: "Best-effort delivery concept: UDP does not maintain timers or retransmission queues. The application layer resolver must time out and re-query.",
            type: "pkt-udp",
            direction: "none",
            route: "none",
            senderState: "STATELESS (No Action)",
            receiverState: "STATELESS",
            inspector: {
              protocol: "UDP",
              srcPort: "N/A",
              dstPort: "N/A",
              seqNum: "N/A",
              ackNum: "N/A",
              flags: ["NONE"],
              headerLen: "N/A",
              payloadLen: "N/A",
              payload: "UDP has no built-in recovery mechanism.",
              checksum: "N/A"
            }
          }
        ]
      }
    }
  };

  // --- State Variables ---
  let currentProtocol = "tcp";
  let currentScenarioKey = "standard";
  let currentStepIndex = -1;
  let playTimer = null;
  let playbackSpeed = 1.0;

  // --- DOM Elements ---
  const el = id => document.getElementById(id);

  // Tab navigation elements
  const tabSimTcp = el("tabSimTcp");
  const tabSimUdp = el("tabSimUdp");
  const tabComparison = el("tabComparison");
  const tabTheory = el("tabTheory");
  const tabExam = el("tabExam");

  const panelSim = el("panelSim");
  const panelComparison = el("panelComparison");
  const panelTheory = el("panelTheory");
  const panelExam = el("panelExam");

  // Simulation controls
  const scenarioSelect = el("scenarioSelect");
  const btnPrev = el("btnPrev");
  const btnNext = el("btnNext");
  const btnPlay = el("btnPlay");
  const btnReset = el("btnReset");

  // Speed buttons
  const speedBtns = document.querySelectorAll(".speed-btn");

  // Scene elements
  const packetLayer = el("packetAnimLayer");
  const bannerBadge = el("bannerBadge");
  const bannerDesc = el("bannerDesc");
  const linkR1 = el("linkR1");
  const linkR2 = el("linkR2");
  const linkVirtual = el("linkVirtual");

  // Node states
  const senderSocketState = el("senderSocketState");
  const receiverSocketState = el("receiverSocketState");

  // Metric displays
  const metricStep = el("metricStep");
  const metricDelay = el("metricDelay");
  const metricHeader = el("metricHeader");
  const metricState = el("metricState");

  // Side timeline & Inspector
  const stepTimeline = el("stepTimeline");
  const inspProtocol = el("inspProtocol");
  const inspPduType = el("inspPduType");
  const inspSrcPort = el("inspSrcPort");
  const inspDstPort = el("inspDstPort");
  const inspSeq = el("inspSeq");
  const inspAck = el("inspAck");
  const inspHdrLen = el("inspHdrLen");
  const inspPayloadLen = el("inspPayloadLen");
  const inspFlagsList = el("inspFlagsList");
  const inspPayload = el("inspPayload");
  const inspChecksum = el("inspChecksum");

  // --- Helper Methods ---
  function getActiveSteps() {
    return SCENARIOS[currentProtocol][currentScenarioKey].steps;
  }

  function updateScenarioDropdown() {
    const scenarios = SCENARIOS[currentProtocol];
    scenarioSelect.innerHTML = "";
    Object.keys(scenarios).forEach(key => {
      const opt = document.createElement("option");
      opt.value = key;
      opt.textContent = scenarios[key].name;
      if (key === currentScenarioKey) opt.selected = true;
      scenarioSelect.appendChild(opt);
    });
  }

  function switchMainTab(activeTabId) {
    [tabSimTcp, tabSimUdp, tabComparison, tabTheory, tabExam].forEach(tab => {
      tab.classList.toggle("active", tab.id === activeTabId);
    });

    panelSim.classList.toggle("active", activeTabId === "tabSimTcp" || activeTabId === "tabSimUdp");
    panelComparison.classList.toggle("active", activeTabId === "tabComparison");
    panelTheory.classList.toggle("active", activeTabId === "tabTheory");
    panelExam.classList.toggle("active", activeTabId === "tabExam");

    if (activeTabId === "tabSimTcp") {
      setProtocol("tcp");
    } else if (activeTabId === "tabSimUdp") {
      setProtocol("udp");
    }
  }

  function setProtocol(protocol) {
    stopPlayback();
    currentProtocol = protocol;
    currentScenarioKey = Object.keys(SCENARIOS[protocol])[0];
    currentStepIndex = -1;

    tabSimTcp.classList.toggle("active", protocol === "tcp");
    tabSimUdp.classList.toggle("active", protocol === "udp");

    updateScenarioDropdown();
    renderTimelineList();
    renderStep();
  }

  function setScenario(scenarioKey) {
    stopPlayback();
    currentScenarioKey = scenarioKey;
    currentStepIndex = -1;
    renderTimelineList();
    renderStep();
  }

  function renderTimelineList() {
    const steps = getActiveSteps();
    stepTimeline.innerHTML = steps.map((s, idx) => `
      <div class="timeline-step-item ${idx === currentStepIndex ? 'active' : ''}" data-step="${idx}">
        <div class="step-badge-no">${idx + 1}</div>
        <div class="step-content-box">
          <strong>${s.label}</strong>
          <p>${s.desc}</p>
        </div>
      </div>
    `).join("");

    // Add click listeners to step items
    stepTimeline.querySelectorAll(".timeline-step-item").forEach(item => {
      item.addEventListener("click", () => {
        stopPlayback();
        const stepNum = parseInt(item.getAttribute("data-step"), 10);
        currentStepIndex = stepNum;
        renderStep();
      });
    });
  }

  function getNodeCoordinates(nodeName) {
    // Percentage coordinates inside 100% relative container
    switch(nodeName) {
      case "sender": return { x: 14, y: 50 };
      case "r1": return { x: 50, y: 24 };
      case "r2": return { x: 50, y: 76 };
      case "receiver": return { x: 86, y: 50 };
      default: return { x: 50, y: 50 };
    }
  }

  function renderStep() {
    const steps = getActiveSteps();
    const totalSteps = steps.length;

    // Update buttons state
    btnPrev.disabled = currentStepIndex <= 0;
    btnNext.disabled = currentStepIndex >= totalSteps - 1;

    // Update metrics
    metricStep.textContent = `${Math.max(0, currentStepIndex + 1)} / ${totalSteps}`;
    metricDelay.textContent = currentProtocol === "tcp" ? "1 RTT Handshake" : "0 RTT (Instant)";
    metricHeader.textContent = currentProtocol === "tcp" ? "20–60 Bytes" : "8 Bytes (Fixed)";

    // Update active highlight in timeline
    stepTimeline.querySelectorAll(".timeline-step-item").forEach((item, idx) => {
      item.classList.toggle("active", idx === currentStepIndex);
    });

    // Clear animations & link highlights
    packetLayer.innerHTML = "";
    linkR1.classList.remove("active-link", "udp-link");
    linkR2.classList.remove("active-link", "udp-link");
    linkVirtual.classList.remove("active-link");

    if (currentStepIndex < 0) {
      // Initial idle state
      bannerBadge.textContent = "SYSTEM READY";
      bannerBadge.style.color = "var(--primary-cyan)";
      bannerDesc.textContent = currentProtocol === "tcp"
        ? "TCP mode selected. Click 'Next Step' or 'Play Demo' to observe connection establishment, byte stream transfer, and 4-way termination."
        : "UDP mode selected. Click 'Next Step' or 'Play Demo' to observe independent datagram transmission without connection establishment.";
      
      senderSocketState.textContent = currentProtocol === "tcp" ? "CLOSED" : "STATELESS";
      senderSocketState.className = "node-socket-state " + (currentProtocol === "tcp" ? "state-closed" : "state-stateless");
      receiverSocketState.textContent = currentProtocol === "tcp" ? "LISTEN" : "STATELESS";
      receiverSocketState.className = "node-socket-state " + (currentProtocol === "tcp" ? "state-listen" : "state-stateless");
      metricState.textContent = currentProtocol === "tcp" ? "Closed / Listen" : "Stateless";

      clearInspector();
      return;
    }

    const step = steps[currentStepIndex];

    // Banner text
    bannerBadge.textContent = `STEP ${currentStepIndex + 1} OF ${totalSteps}`;
    bannerDesc.innerHTML = `<strong>${step.label}:</strong> ${step.desc} <span style="display:block;margin-top:4px;color:var(--text-muted);font-size:11px;">${step.note}</span>`;

    // Sockets and states
    senderSocketState.textContent = step.senderState;
    senderSocketState.className = `node-socket-state ${getStateClass(step.senderState)}`;
    receiverSocketState.textContent = step.receiverState;
    receiverSocketState.className = `node-socket-state ${getStateClass(step.receiverState)}`;
    metricState.textContent = `${step.senderState} / ${step.receiverState}`;

    // Highlight links
    if (step.route.includes("r1")) {
      linkR1.classList.add(currentProtocol === "tcp" ? "active-link" : "udp-link");
    }
    if (step.route.includes("r2")) {
      linkR2.classList.add(currentProtocol === "tcp" ? "active-link" : "udp-link");
    }
    if (currentProtocol === "tcp" && step.senderState === "ESTABLISHED" && step.receiverState === "ESTABLISHED") {
      linkVirtual.classList.add("active-link");
    }

    // Packet Animation
    if (step.direction !== "none") {
      animatePacket(step);
    }

    // Update Packet Inspector
    updateInspector(step.inspector);
  }

  function getStateClass(stateStr) {
    if (!stateStr) return "state-closed";
    const s = stateStr.toUpperCase();
    if (s.includes("LISTEN")) return "state-listen";
    if (s.includes("SYN_SENT")) return "state-syn-sent";
    if (s.includes("SYN_RCVD")) return "state-syn-rcvd";
    if (s.includes("ESTABLISHED")) return "state-established";
    if (s.includes("CLOSE_WAIT") || s.includes("FIN_WAIT") || s.includes("LAST_ACK") || s.includes("TIME_WAIT")) return "state-closing";
    if (s.includes("CLOSED")) return "state-closed";
    return "state-stateless";
  }

  function animatePacket(step) {
    const isForward = step.direction === "to-receiver";
    const startCoord = getNodeCoordinates(isForward ? "sender" : "receiver");
    const endCoord = getNodeCoordinates(isForward ? "receiver" : "sender");
    const midRouter = step.route.includes("r2") ? getNodeCoordinates("r2") : getNodeCoordinates("r1");
    const isDropped = step.type === "pkt-dropped";

    const packet = document.createElement("div");
    packet.className = `packet-pill ${step.type}`;
    packet.textContent = getPillLabel(step);

    // Initial position at start node
    packet.style.left = `${startCoord.x}%`;
    packet.style.top = `${startCoord.y}%`;
    packetLayer.appendChild(packet);

    const legDuration = (750 / playbackSpeed);

    // Leg 1: Start node to Router
    requestAnimationFrame(() => {
      packet.style.transition = `left ${legDuration}ms ease-in, top ${legDuration}ms ease-in`;
      packet.style.left = `${midRouter.x}%`;
      packet.style.top = `${midRouter.y}%`;

      setTimeout(() => {
        if (isDropped) {
          // Visual drop effect at router
          packet.style.transition = "all 0.4s ease";
          packet.style.transform = "translate(-50%, -50%) scale(1.4)";
          packet.style.background = "#ef4444";
          packet.textContent = "DROPPED ✕";
          setTimeout(() => {
            packet.style.opacity = "0";
            packet.style.transform = "translate(-50%, -50%) scale(0.2)";
          }, 450);
          return;
        }

        // Leg 2: Router to Destination
        packet.style.transition = `left ${legDuration}ms ease-out, top ${legDuration}ms ease-out`;
        packet.style.left = `${endCoord.x}%`;
        packet.style.top = `${endCoord.y}%`;
      }, legDuration + 50);
    });
  }

  function getPillLabel(step) {
    if (step.type === "pkt-syn") return "TCP SYN";
    if (step.type === "pkt-syn-ack") return "SYN-ACK";
    if (step.type === "pkt-ack") return "TCP ACK";
    if (step.type === "pkt-data") return "TCP DATA";
    if (step.type === "pkt-fin") return "TCP FIN";
    if (step.type === "pkt-udp") return "UDP D-GRAM";
    if (step.type === "pkt-dropped") return "PACKET";
    return "PDU";
  }

  function updateInspector(insp) {
    if (!insp) {
      clearInspector();
      return;
    }
    inspProtocol.textContent = insp.protocol;
    inspPduType.textContent = insp.protocol === "TCP" ? "Segment" : "Datagram";
    inspSrcPort.textContent = insp.srcPort;
    inspDstPort.textContent = insp.dstPort;
    inspSeq.textContent = insp.seqNum;
    inspAck.textContent = insp.ackNum;
    inspHdrLen.textContent = insp.headerLen;
    inspPayloadLen.textContent = insp.payloadLen;
    inspPayload.textContent = insp.payload;
    inspChecksum.textContent = insp.checksum;

    // Render TCP Flags
    const allFlags = ["SYN", "ACK", "FIN", "RST", "PSH", "URG"];
    inspFlagsList.innerHTML = allFlags.map(f => {
      const isActive = insp.flags && insp.flags.includes(f);
      return `<span class="flag-chip ${isActive ? 'active-flag' : ''}">${f}</span>`;
    }).join("");
  }

  function clearInspector() {
    inspProtocol.textContent = currentProtocol.toUpperCase();
    inspPduType.textContent = "Awaiting Transmission";
    inspSrcPort.textContent = "--";
    inspDstPort.textContent = "--";
    inspSeq.textContent = "--";
    inspAck.textContent = "--";
    inspHdrLen.textContent = "--";
    inspPayloadLen.textContent = "--";
    inspPayload.textContent = "No packet currently in transit.";
    inspChecksum.textContent = "--";
    inspFlagsList.innerHTML = `<span class="flag-chip">NONE</span>`;
  }

  function nextStep() {
    const steps = getActiveSteps();
    if (currentStepIndex < steps.length - 1) {
      currentStepIndex++;
      renderStep();
    } else {
      stopPlayback();
    }
  }

  function prevStep() {
    if (currentStepIndex > 0) {
      currentStepIndex--;
      renderStep();
    }
  }

  function resetSimulation() {
    stopPlayback();
    currentStepIndex = -1;
    renderStep();
  }

  function togglePlayback() {
    if (playTimer) {
      stopPlayback();
    } else {
      startPlayback();
    }
  }

  function startPlayback() {
    const steps = getActiveSteps();
    if (currentStepIndex >= steps.length - 1) {
      currentStepIndex = -1;
    }
    btnPlay.textContent = "⏸ Pause Demo";
    btnPlay.classList.add("btn-primary");
    nextStep();

    const intervalTime = Math.max(1600, 2200 / playbackSpeed);
    playTimer = setInterval(() => {
      if (currentStepIndex >= steps.length - 1) {
        stopPlayback();
      } else {
        nextStep();
      }
    }, intervalTime);
  }

  function stopPlayback() {
    if (playTimer) {
      clearInterval(playTimer);
      playTimer = null;
    }
    btnPlay.textContent = "▶ Play Demo";
    btnPlay.classList.remove("btn-primary");
  }

  // --- Event Listeners Setup ---
  function setupEventListeners() {
    // Navigation Tabs
    tabSimTcp.addEventListener("click", () => switchMainTab("tabSimTcp"));
    tabSimUdp.addEventListener("click", () => switchMainTab("tabSimUdp"));
    tabComparison.addEventListener("click", () => switchMainTab("tabComparison"));
    tabTheory.addEventListener("click", () => switchMainTab("tabTheory"));
    tabExam.addEventListener("click", () => switchMainTab("tabExam"));

    // Scenario Dropdown
    scenarioSelect.addEventListener("change", (e) => setScenario(e.target.value));

    // Playback buttons
    btnPrev.addEventListener("click", prevStep);
    btnNext.addEventListener("click", nextStep);
    btnPlay.addEventListener("click", togglePlayback);
    btnReset.addEventListener("click", resetSimulation);

    // Speed Controls
    speedBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        speedBtns.forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        playbackSpeed = parseFloat(btn.getAttribute("data-speed"));
        if (playTimer) {
          stopPlayback();
          startPlayback();
        }
      });
    });

    // Theme Toggle
    const themeToggleBtn = el("themeToggleBtn");
    const themeIcon = el("themeIcon");
    const themeLabel = el("themeLabel");
    if (themeToggleBtn) {
      themeToggleBtn.addEventListener("click", () => {
        document.body.classList.toggle("dark-theme");
        const isDark = document.body.classList.contains("dark-theme");
        if (themeIcon) themeIcon.textContent = isDark ? "☀️" : "🌙";
        if (themeLabel) themeLabel.textContent = isDark ? "Light Theme" : "Dark Theme";
      });
    }

    // Keyboard Shortcuts
    window.addEventListener("keydown", (e) => {
      if (e.target.tagName === "INPUT" || e.target.tagName === "SELECT") return;
      if (e.key === "ArrowRight") {
        e.preventDefault();
        nextStep();
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        prevStep();
      } else if (e.key === " " || e.code === "Space") {
        e.preventDefault();
        togglePlayback();
      } else if (e.key === "r" || e.key === "R") {
        e.preventDefault();
        resetSimulation();
      }
    });
  }

  // --- Initialization ---
  function init() {
    setupEventListeners();
    setProtocol("tcp");
  }

  init();
})();
