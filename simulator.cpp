#include <iostream>
#include <vector>
#include <string>
#include <list>
#include <map>
#include <memory>
#include <unordered_map>
#include <fstream>
#include <getopt.h>
#include <sstream>
#include <cstdint>

struct IpPacket {
    std::vector<bool> bits; // The entire packet as a sequence of bits
    std::string payload; // The payload as a string
};

struct IpPrefix {
    std::string network_address;
    int prefix_length;

    bool operator==(const IpPrefix& other) const {
        return network_address == other.network_address && prefix_length == other.prefix_length;
    }

    bool operator<(const IpPrefix& other) const {
        if (network_address != other.network_address)
            return network_address < other.network_address;
        return prefix_length < other.prefix_length;
    }
};

enum class OriginType {
    IGP = 0,
    EGP = 1,
    INCOMPLETE = 2
};

struct Route {
    IpPrefix prefix;
    std::string next_hop_ip;
    std::list<int> as_path;
    int local_pref = 100;
    int med = 0;
    OriginType origin;
};

enum class SessionState {
    IDLE,
    CONNECT,
    OPEN_SENT,
    OPEN_CONFIM,
    ESTABLISHED
};

enum class MessageType {
    OPEN = 1,
    UPDATE = 2,
    NOTIFICATION = 3,
    KEEPALIVE = 4
};

enum class PolicyDirection {
    INBOUND,
    OUTBOUND
};

enum class PolicyAction {
    PERMIT,
    DENY,
    SET_LOCAL_PREF,
    AS_PATH_PREPEND
};

struct Header {
    MessageType type;
};

struct KeepaliveMessage : public Header {
    KeepaliveMessage() { type = MessageType::KEEPALIVE; }
};

struct NotificationMessage : public Header {
    NotificationMessage() { type = MessageType::NOTIFICATION; }
    int error_code;
};

struct OpenMessage : public Header {
    OpenMessage() { type = MessageType::OPEN; }
    std::string router_id;
    uint32_t as_number; // Changed to uint32_t to support 4-byte ASNs
};

struct UpdateMessage : public Header {
    UpdateMessage() { type = MessageType::UPDATE; }
    std::vector<Route> advertised_routes;
    std::vector<IpPrefix> withdrawn_routes;
};

struct Policy {
    std::string rule_name;
    PolicyDirection direction;
    PolicyAction action;
    std::string match_peer_ip;
    IpPrefix match_prefix;
    int action_value;
};

class Router;

struct Peer {
    std::string peer_ip;
    uint32_t peer_as;
    SessionState state;
    Router* local_router;

    Peer(const std::string& ip, uint32_t as, Router* router)
        : peer_ip(ip), peer_as(as), state(SessionState::IDLE), local_router(router) {}
};

class Router {
public:
    std::string router_id;
    uint32_t as_number; // Changed to uint32_t to support 4-byte ASNs
    static std::map<std::string, Router*> network;
    std::vector<Policy> policies;

    Router(const std::string& id, uint32_t as_num) : router_id_(id), as_number_(as_num), router_id(id), as_number(as_num) {
        network[id] = this;
    }

    ~Router() = default;
    
    Router(const Router&) = delete;
    Router& operator=(const Router&) = delete;
    Router(Router&&) = default;
    Router& operator=(Router&&) = default;

    void add_peer(const std::string& ip, uint32_t as) {
        peers_.emplace(ip, Peer(ip, as, this));
    }

    void originate_route(const IpPrefix& prefix) {
        std::cout << "Router " << router_id << " originating route " 
                  << prefix.network_address << "/" << prefix.prefix_length << std::endl;
        Route new_route;
        new_route.prefix = prefix;
        new_route.next_hop_ip = router_id;
        new_route.as_path.push_back(this->as_number);
        new_route.origin = OriginType::IGP;

        routing_table_[prefix] = new_route;

        UpdateMessage update;
        update.advertised_routes.push_back(new_route);
        for(auto const& [peer_ip, peer] : peers_) {
            if(peer.state == SessionState::ESTABLISHED) {
                send_message(peer_ip, update);
            }
        }
    }

    void tick() {
        for (auto& [peer_ip, peer] : peers_) {
            if (peer.state == SessionState::IDLE) {
                std::cout << router_id << " -> " << peer_ip << ": Sending OPEN." << std::endl;
                OpenMessage open;
                open.router_id = this->router_id;
                open.as_number = this->as_number;
                send_message(peer_ip, open);
                peer.state = SessionState::OPEN_SENT;
            } else if (peer.state == SessionState::ESTABLISHED) {
                // In a real sim, you'd do this on a timer
                // std::cout << router_id << " -> " << peer_ip << ": Sending KEEPALIVE." << std::endl;
                KeepaliveMessage keepalive;
                send_message(peer_ip, keepalive);
            }
        }
    }

    void receive_message(const std::string& from_ip, const Header& message) { //IP address of the sender peer and the BGP message itself
        Peer& peer = peers_.at(from_ip);
        switch (message.type) {
            case MessageType::OPEN:
                handle_open(peer, static_cast<const OpenMessage&>(message));
                break;
            case MessageType::UPDATE:
                handle_update(peer, static_cast<const UpdateMessage&>(message));
                break;
            case MessageType::KEEPALIVE:
                handle_keepalive(peer, static_cast<const KeepaliveMessage&>(message));
                break;
            case MessageType::NOTIFICATION:
                 std::cout << router_id << " <- " << peer.peer_ip << ": Received NOTIFICATION. Tearing down session." << std::endl;
                peer.state = SessionState::IDLE;
                break;
        }
    }

    static void construct_packet_bits(IpPacket& packet, const std::string& src_ip, const std::string& dest_ip, const std::string& payload) {
        packet.bits.clear();
        // Version (4 bits) + IHL (4 bits) -> 0x45 (IPv4, 5*4=20 byte header)
        append_uint_to_bits(packet.bits, 0x45, 8);
        // Differentiated Services Code Point (8 bits) - unused
        append_uint_to_bits(packet.bits, 0, 8);
        
        // Total Length (16 bits) in bytes
        uint16_t total_length = 20 + payload.length();
        append_uint_to_bits(packet.bits, total_length, 16);

        // Identification (16 bits) - unused
        append_uint_to_bits(packet.bits, 0, 16);

        // Flags (3 bits) + Fragment offset (13 bits) - unused
        append_uint_to_bits(packet.bits, 0, 16);
        
        // TTL (8 bits) - set to a default of 64
        append_uint_to_bits(packet.bits, 64, 8);
        
        // Protocol (8 bits) - unused for this simulation
        append_uint_to_bits(packet.bits, 0, 8);

        // Header Checksum (16 bits) - unused, set to 0
        append_uint_to_bits(packet.bits, 0, 16);

        // Source IP (32 bits)
        std::vector<bool> src_ip_bits = ip_string_to_bits(src_ip);
        packet.bits.insert(packet.bits.end(), src_ip_bits.begin(), src_ip_bits.end());

        // Destination IP (32 bits)
        std::vector<bool> dest_ip_bits = ip_string_to_bits(dest_ip);
        packet.bits.insert(packet.bits.end(), dest_ip_bits.begin(), dest_ip_bits.end());
        
        // --- Payload ---
        append_string_to_bits(packet.bits, payload);
        
        // Also store parsed values in the struct for convenience
        packet.source_ip = src_ip;
        packet.destination_ip = dest_ip;
        packet.payload = payload;
    }

    /**
     * Parses a packet's bit vector to extract header fields and payload.
     * * @param packet is the IpPacket to parse. Its 'bits' vector is read, and the 
     * source_ip, destination_ip, and payload fields are populated.
     * @return true if parsing was successful, false otherwise.
     */
    static bool parse_packet(IpPacket& packet) {
        if (packet.bits.size() < 160) { // Minimum header size is 20 bytes (160 bits)
            return false;
        }

        // Version (bits 0-3), IHL (bits 4-7)
        uint8_t version_ihl = bits_to_uint(packet.bits, 0, 8);
        uint8_t version = version_ihl >> 4;
        uint8_t ihl = version_ihl & 0x0F;
        
        if (version != 4 || ihl < 5) { // Checks for IPv4 and min header length
            return false;
        }
        
        // Total Length in bytes (bits 16-31)
        uint16_t total_length_bytes = bits_to_uint(packet.bits, 16, 16);
        
        if (packet.bits.size() != total_length_bytes * 8) { // Integrity check
            return false;
        }
        
        size_t header_len_bits = ihl * 32;

        // Source IP (bits 96-127)
        packet.source_ip = bits_to_ip_string(packet.bits, 96);
        
        // Destination IP (bits 128-159)
        packet.destination_ip = bits_to_ip_string(packet.bits, 128);
        
        // Payload
        size_t payload_len_bytes = total_length_bytes - (header_len_bits / 8);
        packet.payload = bits_to_string(packet.bits, header_len_bits, payload_len_bytes);
        
        return true;
    }


    void forward_packet(const IpPacket& packet) {
        std::cout << "\nPacket arriving: " << router_id << ": Received packet for destination " << packet.destination_ip << std::endl; // The router receives a packet to forward

        const Route* best_match_route = nullptr; // No best match has been found yet
        int longest_match_len = -1; // Any valid prefix length will be longer than this

        for (const auto& [prefix, route] : routing_table_) {
            // Simple string-based check for Longest Prefix Match
            if (packet.destination_ip.rfind(prefix.network_address, 0) == 0) {
                if (prefix.prefix_length > longest_match_len) {
                    longest_match_len = prefix.prefix_length;
                    best_match_route = &route;
                }
            }
        }
        // best_match_route now points to the best matching route, if any: best match is the one with the most specific prefix (longest in bits)
        if (best_match_route) {
            std::cout << "  Match found for prefix " << best_match_route->prefix.network_address << "/" << best_match_route->prefix.prefix_length << "." << std::endl;
            std::cout << "  Forwarding packet to next hop: " << best_match_route->next_hop_ip << std::endl;
        } else {
            std::cout << "  No route found. Packet dropped." << std::endl;
        }
    }

    void print_routing_table() {
        std::cout << "\n--- Routing Table for " << router_id << " (AS " << as_number << ") ---" << std::endl;
        if(routing_table_.empty()) {
            std::cout << "(Table is empty)" << std::endl;
            return;
        }
        for(const auto& [prefix, route] : routing_table_) {
            std::cout << "  " << prefix.network_address << "/" << prefix.prefix_length 
                      << " -> next-hop: " << route.next_hop_ip
                      << ", AS_PATH: [ ";
            for(uint32_t as : route.as_path) {
                std::cout << as << " ";
            }
            std::cout << "]" << std::endl;
        }
        std::cout << "------------------------------------------" << std::endl;
    }

    void add_policy_rule(const Policy& rule) {
        policies.push_back(rule);
    }

private:
    std::string router_id_;
    uint32_t as_number_;
    std::map<std::string, Peer> peers_; // Keyed by peer IP
    std::map<IpPrefix, Route> routing_table_; // for the routing table, each IpPrefix key represents a network prefix (address + length)

    void send_message(const std::string& to_ip, const Header& message) {
        if (network.count(to_ip)) {
            network[to_ip]->receive_message(this->router_id, message);
        }
    }

    void handle_open(Peer& peer, const OpenMessage& message) {
        std::cout << router_id << " <- " << peer.peer_ip << ": Received OPEN." << std::endl;
        if (peer.state == SessionState::OPEN_SENT) {
            std::cout << "Session ESTABLISHED with " << peer.peer_ip << std::endl;
            peer.state = SessionState::ESTABLISHED;
            KeepaliveMessage keepalive;
            send_message(peer.peer_ip, keepalive);

            // Now that we're connected, advertise our own routes
            if(!routing_table_.empty()){
                UpdateMessage update_for_new_peer;
                for(const auto& [prefix, route] : routing_table_) {
                     // Only advertise routes we originated ourselves
                    if(route.next_hop_ip == "0.0.0.0") {
                        update_for_new_peer.advertised_routes.push_back(route);
                    }
                }
                if(!update_for_new_peer.advertised_routes.empty()){
                    send_message(peer.peer_ip, update_for_new_peer);
                }
            }
        }
    }

    void handle_keepalive(Peer& peer, const KeepaliveMessage& message) {
         if (peer.state == SessionState::ESTABLISHED) {
            // std::cout << router_id << " <- " << peer.peer_ip << ": Received KEEPALIVE." << std::endl;
        }
    }

    void handle_update(Peer& peer, const UpdateMessage& message) {
        if (peer.state != SessionState::ESTABLISHED) return;
        std::cout << router_id << " <- " << peer.peer_ip << ": Received UPDATE." << std::endl;

        bool table_changed = false;

        for (const auto& new_route_info : message.advertised_routes) {
            Route candidate_route = new_route_info;
            candidate_route.next_hop_ip = peer.peer_ip; // The next hop is the peer who sent us the message

            if (!this->apply_inbound_policies(candidate_route, peer)) {
                std::cout << "   Route " << candidate_route.prefix.network_address << "/" << candidate_route.prefix.prefix_length 
                          << " denied by inbound policy from " << peer.peer_ip << std::endl;
                continue; // Skip this route
            }


            // BGP decision process
            if (routing_table_.count(candidate_route.prefix) == 0) {
                // If we have no route, we accept this one
              routing_table_[candidate_route.prefix] = candidate_route;
            table_changed = true;
        } else {
            Route& existing_route = routing_table_.at(candidate_route.prefix);
            // Higher LOCAL_PREF is better
            if (candidate_route.local_pref > existing_route.local_pref) {
                existing_route = candidate_route;
                table_changed = true;
            } 
            // Shorter AS_PATH is better (only if LOCAL_PREF is equal)
            else if (candidate_route.local_pref == existing_route.local_pref &&
                       candidate_route.as_path.size() < existing_route.as_path.size()) {
                existing_route = candidate_route;
                table_changed = true;
            }
        }
    }

        if (table_changed) {
            std::cout << "   " << router_id << "'s routing table changed. Propagating updates." << std::endl;
            // Propagate the best routes to our other peers
            for (auto const& [next_peer_ip, next_peer] : peers_) {
                if (next_peer_ip != peer.peer_ip && next_peer.state == SessionState::ESTABLISHED) {
                    UpdateMessage downstream_update;
                    for (const auto& [prefix, route] : routing_table_) {
                        Route new_advertisement = route;
                        new_advertisement.as_path.push_front(this->as_number); // Prepend our AS

                        if (!apply_outbound_policies(new_advertisement, next_peer)) {
                            std::cout << "   Route " << new_advertisement.prefix.network_address << "/" << new_advertisement.prefix.prefix_length 
                                      << " denied by outbound policy to " << next_peer.peer_ip << std::endl;
                            continue; // Skip this route
                        }
                        downstream_update.advertised_routes.push_back(new_advertisement);
                    }
                    send_message(next_peer_ip, downstream_update);
                }
            }
        }
    }

    bool apply_inbound_policies(Route& route, const Peer& peer) { // Modify the route in place based on policy action
        for (const auto& policy : policies) {
            if (policy.direction == PolicyDirection::INBOUND) {
                if (policy.match_peer_ip == peer.peer_ip || policy.match_prefix == route.prefix) {
                    if (policy.action == PolicyAction::DENY) {
                        return false; // Route is denied
                    }
                    else if (policy.action == PolicyAction::SET_LOCAL_PREF) {
                        route.local_pref = policy.action_value;
                    } else if (policy.action == PolicyAction::AS_PATH_PREPEND) {
                        for (int i = 0; i < policy.action_value; ++i) {
                            route.as_path.push_front(this->as_number);
                        }
                    }
                    // Actions like PERMIT are implicit; if no DENY matches, the route is permitted
                }
            }
        }
        return true; // Route is permitted
    }

    bool apply_outbound_policies(Route& route, const Peer& peer) {
        for (const auto& policy : policies) {
            if (policy.direction == PolicyDirection::OUTBOUND) {
                if (policy.match_peer_ip == peer.peer_ip || policy.match_prefix == route.prefix) { // Check if the policy matches the peer IP or prefix
                    if (policy.action == PolicyAction::DENY) {
                        return false;
                    } else if (policy.action == PolicyAction::SET_LOCAL_PREF) {
                        route.local_pref = policy.action_value;
                    } else if (policy.action == PolicyAction::AS_PATH_PREPEND) {
                        for (int i = 0; i < policy.action_value; ++i) {
                            route.as_path.push_front(this->as_number);
                        }
                    }
                }
            }
        }
        return true;
    }
};

void load_topology(const std::string& filename, std::vector<Router*>& all_routers) {
    std::ifstream infile(filename);
    std::string line;
    enum Section { NONE, ROUTERS, LINKS };
    Section current = NONE;

    // Temporary map for AS lookup
    std::map<std::string, int> router_as_map;

    while (std::getline(infile, line)) {
        // Remove comments and trim
        auto comment_pos = line.find('#');
        if (comment_pos != std::string::npos) line = line.substr(0, comment_pos);
        std::istringstream iss(line);
        std::string token;
        if (!(iss >> token)) continue; // skip empty

        if (token == "[Routers]") {
            current = ROUTERS;
            continue;
        }
        if (token == "[Links]") {
            current = LINKS;
            continue;
        }

        if (current == ROUTERS) {
            // RouterID AS_Number
            std::string router_id = token;
            uint32_t asn;
            if (!(iss >> asn)) continue;
            auto* r = new Router(router_id, asn);
            all_routers.push_back(r);
            Router::network[router_id] = r;
            router_as_map[router_id] = asn;
        } else if (current == LINKS) {
            // Format: RouterID1 RouterID2
            std::string router1 = token, router2;
            if (!(iss >> router2)) continue;
            // Add peers both ways
            uint32_t as1 = router_as_map[router1];
            uint32_t as2 = router_as_map[router2];
            if (Router::network.count(router1) && Router::network.count(router2)) {
                Router::network[router1]->add_peer(router2, as2);
                Router::network[router2]->add_peer(router1, as1);
            }
        }
    }
}

int main(int argc, char* argv[]) {
    std::string topology_file;
    int opt;
    while ((opt = getopt(argc, argv, "c:")) != -1) { // -c for config file
        if (opt == 'c') topology_file = optarg;
    }

    std::vector<Router*> all_routers;
    if (!topology_file.empty()) {
        load_topology(topology_file, all_routers);
        std::cout << "\n--- Establishing BGP Sessions ---" << std::endl;
    for (int i = 0; i < 3; ++i) {
        std::cout << "\n--- Tick " << i + 1 << " ---" << std::endl;
        for(Router* r : all_routers) {
            r->tick();
        }
    }

    std::cout << "\n--- Route Origination and Propagation ---" << std::endl;
    // Example: originate a route from the first router
    if (!all_routers.empty()) {
        all_routers[0]->originate_route({"10.10.10.0", 24});
    }

    for (int i = 0; i < 5; ++i) {
        std::cout << "\n--- Tick " << i + 4 << " ---" << std::endl;
        for(Router* r : all_routers) {
            r->tick();
        }
    }

    // Print routing tables for all routers
    for(Router* r : all_routers) {
        r->print_routing_table();
    }

    // Optional: test packet forwarding
    if (all_routers.size() > 1) {
        IpPacket test_packet;
        test_packet.source_ip = "10.10.10.10";
        test_packet.destination_ip = "10.10.10.20";
        test_packet.payload = "Test!";
        all_routers[0]->forward_packet(test_packet);
    }
    } else {
    std::cout << "--- BGP Simulator Startup ---" << std::endl;

// AS 65001
    Router r1("10.0.1.1", 65001);
    Router r2("10.0.1.2", 65001);
    Router r3("10.0.1.3", 65001);

    // AS 65002
    Router r4("10.0.2.4", 65002);
    Router r5("10.0.2.5", 65002);
    
    // AS 65003
    Router r6("10.0.3.6", 65003);
    Router r7("10.0.3.7", 65003);
    Router r8("10.0.3.8", 65003);
    
    // AS 65004
    Router r9("10.0.4.9", 65004);
    Router r10("10.0.4.10", 65004);

    // Helper vector to easily iterate over all routers
    std::vector<Router*> all_routers = {&r1, &r2, &r3, &r4, &r5, &r6, &r7, &r8, &r9, &r10};

    // Peering topology setup
    
    // iBGP Peering (Full mesh within each AS using Router IDs)
    r1.add_peer(r2.router_id, 65001); r1.add_peer(r3.router_id, 65001);
    r2.add_peer(r1.router_id, 65001); r2.add_peer(r3.router_id, 65001);
    r3.add_peer(r1.router_id, 65001); r3.add_peer(r2.router_id, 65001);
    
    r4.add_peer(r5.router_id, 65002);
    r5.add_peer(r4.router_id, 65002);

    r6.add_peer(r7.router_id, 65003); r6.add_peer(r8.router_id, 65003);
    r7.add_peer(r6.router_id, 65003); r7.add_peer(r8.router_id, 65003);
    r8.add_peer(r6.router_id, 65003); r8.add_peer(r7.router_id, 65003);

    r9.add_peer(r10.router_id, 65004);
    r10.add_peer(r9.router_id, 65004);

    // -- eBGP Peering (Between border routers) --
    r3.add_peer(r4.router_id, 65002);
    r4.add_peer(r3.router_id, 65001);

    r4.add_peer(r6.router_id, 65003);
    r6.add_peer(r4.router_id, 65002);
    
    r5.add_peer(r10.router_id, 65004);
    r10.add_peer(r5.router_id, 65002);
    
    r8.add_peer(r9.router_id, 65004);
    r9.add_peer(r8.router_id, 65003);
    

    // Configuring a policy on AS 65003

    Policy prefer_as65004;
    prefer_as65004.rule_name = "Prefer-AS65004-Path";
    prefer_as65004.direction = PolicyDirection::INBOUND; // Inbound policy on R8
    prefer_as65004.action = PolicyAction::SET_LOCAL_PREF;
    prefer_as65004.match_peer_ip = r9.router_id; // Match routes from R9
    prefer_as65004.action_value = 200; // Default Local Pref is 100
    // r8.add_policy_rule(prefer_as65004); // NOTE: This requires fixing inbound policy modification

    // Simulation ticks
    std::cout << "\n--- Establishing BGP Sessions ---" << std::endl;
    for (int i = 0; i < 3; ++i) {
        std::cout << "\n--- Tick " << i + 1 << " ---" << std::endl;
        for(Router* r : all_routers) {
            r->tick();
        }
    }
    
    std::cout << "\n--- Route Origination and Propagation ---" << std::endl;
    // Each AS originates its own prefix
    r1.originate_route({"172.16.1.0", 24});
    r4.originate_route({"172.16.2.0", 24});
    r7.originate_route({"172.16.3.0", 24});
    r9.originate_route({"172.16.4.0", 24});

    // Run more ticks to allow routes to propagate across the network
    for (int i = 0; i < 5; ++i) {
        std::cout << "\n--- Tick " << i + 4 << " ---" << std::endl;
        for(Router* r : all_routers) {
            r->tick();
        }
    }

    // Final routing tables to verify
    r1.print_routing_table();
    r6.print_routing_table(); // Check this table to see if policy worked
    r9.print_routing_table();
    
    // Packet forwarding test

    IpPacket test_packet;
    test_packet.source_ip = "172.16.3.10"; // From AS 65003
    test_packet.destination_ip = "172.16.1.50"; // To AS 65001
    test_packet.payload = "BGP Policy Test!";

    r7.forward_packet(test_packet);

    return 0;
}
}

std::map<std::string, Router*> Router::network;