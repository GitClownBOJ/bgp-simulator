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
    std::string source_ip;
    std::string destination_ip;
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
    std::string from_ip;
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
    void print_peer_summary() const;
    std::string router_id;
    uint32_t as_number; // Changed to uint32_t to support 4-byte ASNs
    void print_routing_table();
    void tick();
    void originate_route(const IpPrefix& prefix);
    void handle_open(Peer& peer, const OpenMessage& message);
    void handle_keepalive(Peer& peer, const KeepaliveMessage& message);
    void process_inbox(); 
    void send_message(const std::string& to_ip, Header& message); // Note: message is no longer const
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

    static uint64_t bits_to_uint(const std::vector<bool>& bits, size_t offset, int num_bits) {
        uint64_t result = 0;
        for (int i = 0; i < num_bits; ++i) {
            result <<= 1; // Make space for the next bit
            if (offset + i < bits.size() && bits[offset + i]) {
                result |= 1;
            }
        }
        return result;
    }

     static void append_uint_to_bits(std::vector<bool>& bits, uint64_t value, int num_bits) {
        for (int i = num_bits - 1; i >= 0; --i) {
            bits.push_back((value >> i) & 1);
        }
    }

    static void append_string_to_bits(std::vector<bool>& bits, const std::string& s) {
        for (char c : s) {
            append_uint_to_bits(bits, static_cast<uint8_t>(c), 8);
        }
    }

    static std::vector<bool> ip_string_to_bits(const std::string& ip) {
        std::vector<bool> bits;
        std::istringstream iss(ip);
        std::string byte_str;
        while (std::getline(iss, byte_str, '.')) {
            uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str));
            append_uint_to_bits(bits, byte, 8);
        }
        return bits;
    }   

        static std::string bits_to_string(const std::vector<bool>& bits, size_t offset, size_t length_bytes) {
        std::string s = "";
        for (size_t i = 0; i < length_bytes; ++i) {
            // Calculate the starting bit for the current character
            size_t current_offset = offset + (i * 8);
            if (current_offset + 8 > bits.size()) {
                // Avoid reading past the end of the vector
                break; 
            }
            // Convert 8 bits to a number, then cast it to a char
            uint8_t char_code = bits_to_uint(bits, current_offset, 8);
            s += static_cast<char>(char_code);
        }
        return s;
    }

    static std::string bits_to_ip_string(const std::vector<bool>& bits, size_t offset) {
        std::string ip;
        for (int i = 0; i < 4; ++i) {
            if (i > 0) ip += ".";
            uint8_t byte = static_cast<uint8_t>(bits_to_uint(bits, offset + i * 8, 8));
            ip += std::to_string(byte);
        }
        return ip;
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


    void add_policy_rule(const Policy& rule) {
        policies.push_back(rule);
    }

private:
    std::string router_id_;
    uint32_t as_number_;
    std::map<std::string, Peer> peers_; // Keyed by peer IP
    std::map<IpPrefix, Route> routing_table_; // for the routing table, each IpPrefix key represents a network prefix (address + length)
    std::vector<Header*> inbox_;


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

void Router::process_inbox() {
    // Process all messages currently in the inbox
    for (Header* msg : inbox_) {
        // Call the main message handler for each message
        receive_message(msg->from_ip, *msg);
        
        // Clean up the dynamically allocated message copy
        delete msg;
    }
    // Clear the inbox to prepare for the next simulation tick
    inbox_.clear();
}

void Router::send_message(const std::string& to_ip, Header& message) { // Note: message is no longer const
    if (network.count(to_ip)) {
        Router* destination_router = network[to_ip];
        message.from_ip = this->router_id; // Set the sender's IP

        // Create a copy of the message on the heap
        Header* msg_copy;
        switch(message.type) {
            case MessageType::OPEN: 
                msg_copy = new OpenMessage(*static_cast<OpenMessage*>(&message));
                break;
            case MessageType::UPDATE:
                msg_copy = new UpdateMessage(*static_cast<UpdateMessage*>(&message));
                break;
            case MessageType::KEEPALIVE:
                msg_copy = new KeepaliveMessage(*static_cast<KeepaliveMessage*>(&message));
                break;
            case MessageType::NOTIFICATION:
                msg_copy = new NotificationMessage(*static_cast<NotificationMessage*>(&message));
                break;
        }

        // Add the message copy to the destination's inbox
        destination_router->inbox_.push_back(msg_copy);
    }
}

void Router::handle_keepalive(Peer& peer, const KeepaliveMessage& message) {
    if (peer.state == SessionState::OPEN_SENT) {
        peer.state = SessionState::ESTABLISHED;
        std::cout << "Session ESTABLISHED with " << peer.peer_ip << std::endl;

        UpdateMessage update_for_new_peer;
        for (const auto& [prefix, route] : routing_table_) {
            if (route.next_hop_ip == "0.0.0.0" || route.next_hop_ip == this->router_id) {
                update_for_new_peer.advertised_routes.push_back(route);
            }
        }
        if (!update_for_new_peer.advertised_routes.empty()) {
            send_message(peer.peer_ip, update_for_new_peer);
        }

    } else if (peer.state == SessionState::ESTABLISHED) {
        // Normal keepalive to maintain the session
    }
}

void Router::handle_open(Peer& peer, const OpenMessage& message) {
    std::cout << router_id << " <- " << peer.peer_ip << ": Received OPEN." << std::endl;
    
    // When we receive an OPEN, we reply with a KEEPALIVE to confirm we received it.
    KeepaliveMessage keepalive;
    send_message(peer.peer_ip, keepalive);

    // If we haven't sent our own OPEN yet (i.e., we were IDLE), we send it now.
    if (peer.state == SessionState::IDLE) {
        OpenMessage open;
        open.router_id = this->router_id;
        open.as_number = this->as_number;
        send_message(peer.peer_ip, open);
        peer.state = SessionState::OPEN_SENT;
    }
}

void Router::print_routing_table() {
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

void Router::originate_route(const IpPrefix& prefix) {
    std::cout << "Router " << router_id << " originating route " 
              << prefix.network_address << "/" << prefix.prefix_length << std::endl;
              
    Route new_route;
    new_route.prefix = prefix;
    new_route.next_hop_ip = router_id; // Assuming you fix the redundant variable issue
    new_route.as_path.push_back(as_number);
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



void Router::tick() {
    for (auto& [peer_ip, peer] : peers_) {
        if (peer.state == SessionState::IDLE) {
            std::cout << router_id_ << " -> " << peer_ip << ": Sending OPEN." << std::endl;
            OpenMessage open;
            open.router_id = this->router_id_; // Use the private member
            open.as_number = this->as_number_; // Use the private member
            send_message(peer_ip, open);
            peer.state = SessionState::OPEN_SENT;
        } else if (peer.state == SessionState::ESTABLISHED) {
            KeepaliveMessage keepalive;
            send_message(peer_ip, keepalive);
        }
    }
}

void Router::print_peer_summary() const {
    std::cout << "\n--- BGP Peer Summary for " << router_id << " (AS " << as_number << ") ---" << std::endl;
    if (peers_.empty()) {
        std::cout << "(No peers configured)" << std::endl;
        return;
    }
    std::cout << "Peer Address\t\tAS\t\tState\n";
    std::cout << "--------------------------------------------------\n";
    for (const auto& [ip, peer] : peers_) {
        std::string state_str;
        switch (peer.state) {
            case SessionState::IDLE: state_str = "IDLE"; break;
            case SessionState::CONNECT: state_str = "CONNECT"; break;
            case SessionState::OPEN_SENT: state_str = "OPEN_SENT"; break;
            case SessionState::OPEN_CONFIM: state_str = "OPEN_CONFIM"; break;
            case SessionState::ESTABLISHED: state_str = "ESTABLISHED"; break;
            default: state_str = "UNKNOWN"; break;
        }
        std::cout << ip << "\t\t" << peer.peer_as << "\t\t" << state_str << std::endl;
    }
    std::cout << "--------------------------------------------------" << std::endl;
}
void run_simulation_ticks(std::vector<Router*>& routers, int count) {
    for (int i = 0; i < count; ++i) {
         for(Router* r : routers) {
            r->tick();
        }

        // Phase 2: All routers process their received messages
        for(Router* r : routers) {
            r->process_inbox();
        }
    }
}

void print_help() {
    std::cout << "BGP Simulator CLI Commands:\n"
              << "  show ip bgp <router_id>      - Display the BGP routing table for a router (e.g., 'show ip bgp 10.0.1.1').\n"
              << "  show peers <router_id>        - Display the BGP peers and their session status for a router.\n"
              << "  tick [n]                     - Advance the simulation by 'n' ticks (default is 1).\n"
              << "  help                         - Show this help message.\n"
              << "  exit / quit                  - Exit the simulator.\n";
}




int main(int argc, char* argv[]) {
    std::string topology_file;
    int opt;
    while ((opt = getopt(argc, argv, "c:")) != -1) {
        if (opt == 'c') topology_file = optarg;
    }

    std::vector<Router*> all_routers;
    if (!topology_file.empty()) {
        load_topology(topology_file, all_routers);
    } else {
        std::cout << "--- BGP Simulator Startup (Hardcoded Topology) ---" << std::endl;
        // The hardcoded setup logic from your original file should go here
        // This setup should populate the `all_routers` vector
    }

    std::cout << "\n--- Initializing Network and Establishing Sessions... ---" << std::endl;
    run_simulation_ticks(all_routers, 3);

    std::cout << "\n--- Originating Routes and Allowing Network to Converge... ---" << std::endl;
    if (!all_routers.empty()) {
        all_routers[0]->originate_route({"10.10.10.0", 24});
    }
    run_simulation_ticks(all_routers, 5);

    std::cout << "\n\n--- Network converged. Entering interactive CLI. ---" << std::endl;
    print_help();

    std::string line;
    while (true) {
        std::cout << "\nBGP-Sim> ";
        if (!std::getline(std::cin, line)) {
            break;
        }

        std::istringstream iss(line);
        std::vector<std::string> tokens;
        std::string token;
        while (iss >> token) {
            tokens.push_back(token);
        }

        if (tokens.empty()) {
            continue;
        }

        const std::string& command = tokens[0];

        if (command == "exit" || command == "quit") {
            std::cout << "Exiting simulator." << std::endl;
            break;
        } else if (command == "help") {
            print_help();
        } else if (command == "tick") {
            int num_ticks = 1;
            if (tokens.size() > 1) {
                try {
                    num_ticks = std::stoi(tokens[1]);
                } catch (const std::exception&) {
                    std::cout << "Error: Invalid number of ticks." << std::endl;
                    continue;
                }
            }
            std::cout << "Advancing simulation by " << num_ticks << " tick(s)..." << std::endl;
           } else if (command == "neighbor") {
            // Expected format: neighbor <router_id> <peer_ip> remote-as <asn>
            if (tokens.size() == 5 && tokens[3] == "remote-as") {
                const std::string& router_id = tokens[1];
                const std::string& peer_ip = tokens[2];
                const std::string& asn_str = tokens[4];

                if (Router::network.count(router_id) == 0) {
                    std::cout << "Error: Router '" << router_id << "' not found." << std::endl;
                    continue;
                }

                try {
                    uint32_t peer_as = std::stoul(asn_str); // Use stoul for uint32_t
                    Router* router = Router::network[router_id];
                    
                    // The core action: call add_peer()
                    router->add_peer(peer_ip, peer_as);

                    std::cout << "Configured peer " << peer_ip << " (AS " << peer_as 
                              << ") on router " << router_id << "." << std::endl;
                    std::cout << "The neighborship will attempt to establish on the next tick." << std::endl;

                } catch (const std::exception& e) {
                    std::cout << "Error: Invalid AS number '" << asn_str << "'." << std::endl;
                }

            } else {
                std::cout << "Usage: neighbor <router_id> <peer_ip> remote-as <asn>" << std::endl;
            }
       

        } else if (command == "show") {
            if (tokens.size() == 4 && tokens[1] == "ip" && tokens[2] == "bgp") {
                const std::string& router_id = tokens[3];
                if (Router::network.count(router_id)) {
                    Router::network[router_id]->print_routing_table();
                } else {
                    std::cout << "Error: Router '" << router_id << "' not found." << std::endl;
                }
            } else if (tokens.size() == 3 && tokens[1] == "peers") {
                const std::string& router_id = tokens[2];
                if (Router::network.count(router_id)) {
                    Router::network[router_id]->print_peer_summary();
                } else {
                    std::cout << "Error: Router '" << router_id << "' not found." << std::endl;
                }
            }
            else {
                std::cout << "Error: Invalid 'show' command. Type 'help' for syntax." << std::endl;
            }
        } else {
            std::cout << "Error: Unknown command '" << command << "'. Type 'help' for available commands." << std::endl;
        }
    }

    for (Router* r : all_routers) {
        delete r;
    }
    all_routers.clear();

    return 0;
}

std::map<std::string, Router*> Router::network;