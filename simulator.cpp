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
#include <iomanip>

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
    KEEPALIVE = 4,
    TRUST_MESSAGE = 5 // New message type for trust data exchange
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

struct TrustMessage : public Header {
    TrustMessage() { type = MessageType::TRUST_MESSAGE; }
    std::map<std::string, double> trust_data; // Key: Router ID, Value: Trust value (0.0 to 1.0)
};

class Router;

struct Peer {
    std::string peer_ip;
    uint32_t peer_as;
    SessionState state;
    Router* local_router;

    int successful_interactions = 0;
    int total_interactions = 0;

    Peer(const std::string& ip, uint32_t as, Router* router)
        : peer_ip(ip), peer_as(as), state(SessionState::IDLE), local_router(router) {}
};

class Router {
public:
    // --- CHANGE: Added public getters ---
    const std::string& get_router_id() const { return router_id_; }
    uint32_t get_as_number() const { return as_number_; }

    void print_peer_summary() const;
    // --- CHANGE: Redundant public members removed ---
    void print_routing_table();
    void tick(bool verbose);
    void originate_route(const IpPrefix& prefix, bool verbose = true);
    void handle_open(Peer& peer, const OpenMessage& message, bool verbose);
    void handle_keepalive(Peer& peer, const KeepaliveMessage& message, bool verbose);
    void process_inbox(bool verbose); 
    void send_message(const std::string& to_ip, Header& message);
    static std::map<std::string, Router*> network;
    std::vector<Policy> policies;

    void print_trust_table() const;

    // --- CHANGE: Constructor fixed ---
    Router(const std::string& id, uint32_t as_num) : router_id_(id), as_number_(as_num) {
        network[id] = this;
        total_trust_values_[router_id_] = 1.0;
    }

    ~Router() = default;
     
    Router(const Router&) = delete;
    Router& operator=(const Router&) = delete;
    Router(Router&&) = default;
    Router& operator=(Router&&) = default;

    void add_peer(const std::string& ip, uint32_t as) {
        peers_.emplace(ip, Peer(ip, as, this));
    }

    void receive_message(const std::string& from_ip, const Header& message, bool verbose) {
            auto it = peers_.find(from_ip);
    if (it == peers_.end()) {
        if (verbose) {
            std::cout << router_id_ << ": Received message from unknown peer " 
                      << from_ip << ". Ignoring." << std::endl;
        }
        return;
    }
    
    Peer& peer = it->second;
        switch (message.type) {
            case MessageType::OPEN:
                handle_open(peer, static_cast<const OpenMessage&>(message), verbose);
                break;
            case MessageType::UPDATE:
                handle_update(peer, static_cast<const UpdateMessage&>(message), verbose);
                break;
            case MessageType::KEEPALIVE:
                handle_keepalive(peer, static_cast<const KeepaliveMessage&>(message), verbose);
                break;
            case MessageType::NOTIFICATION:
                if (verbose) {
                    std::cout << router_id_ << " <- " << peer.peer_ip << ": Received NOTIFICATION. Tearing down session." << std::endl;
                }
                if (total_trust_values_.count(peer.peer_ip)) {
                    total_trust_values_[peer.peer_ip] /= 2.0;
                }
                peer.state = SessionState::IDLE;
                break;
            case MessageType::TRUST_MESSAGE:
                handle_trust_message(peer, static_cast<const TrustMessage&>(message));
                break;
        }
    }

    static uint64_t bits_to_uint(const std::vector<bool>& bits, size_t offset, int num_bits) {
        uint64_t result = 0;
        for (int i = 0; i < num_bits; ++i) {
            result <<= 1;
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
            size_t current_offset = offset + (i * 8);
            if (current_offset + 8 > bits.size()) {
                break; 
            }
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
        append_uint_to_bits(packet.bits, 0x45, 8);
        append_uint_to_bits(packet.bits, 0, 8);
        uint16_t total_length = 20 + payload.length();
        append_uint_to_bits(packet.bits, total_length, 16);
        append_uint_to_bits(packet.bits, 0, 16);
        append_uint_to_bits(packet.bits, 0, 16);
        append_uint_to_bits(packet.bits, 64, 8);
        append_uint_to_bits(packet.bits, 0, 8);
        append_uint_to_bits(packet.bits, 0, 16);
        std::vector<bool> src_ip_bits = ip_string_to_bits(src_ip);
        packet.bits.insert(packet.bits.end(), src_ip_bits.begin(), src_ip_bits.end());
        std::vector<bool> dest_ip_bits = ip_string_to_bits(dest_ip);
        packet.bits.insert(packet.bits.end(), dest_ip_bits.begin(), dest_ip_bits.end());
        append_string_to_bits(packet.bits, payload);
        packet.source_ip = src_ip;
        packet.destination_ip = dest_ip;
        packet.payload = payload;
    }

    static bool parse_packet(IpPacket& packet) {
        if (packet.bits.size() < 160) {
            return false;
        }
        uint8_t version_ihl = bits_to_uint(packet.bits, 0, 8);
        uint8_t version = version_ihl >> 4;
        uint8_t ihl = version_ihl & 0x0F;
        if (version != 4 || ihl < 5) {
            return false;
        }
        uint16_t total_length_bytes = bits_to_uint(packet.bits, 16, 16);
        if (packet.bits.size() != total_length_bytes * 8) {
            return false;
        }
        size_t header_len_bits = ihl * 32;
        packet.source_ip = bits_to_ip_string(packet.bits, 96);
        packet.destination_ip = bits_to_ip_string(packet.bits, 128);
        size_t payload_len_bytes = total_length_bytes - (header_len_bits / 8);
        packet.payload = bits_to_string(packet.bits, header_len_bits, payload_len_bytes);
        return true;
    }

    void forward_packet(const IpPacket& packet) {
        std::cout << "\nPacket arriving: " << router_id_ << ": Received packet for destination " << packet.destination_ip << std::endl;
        const Route* best_match_route = nullptr;
        int longest_match_len = -1;
        for (const auto& [prefix, route] : routing_table_) {
            if (packet.destination_ip.rfind(prefix.network_address, 0) == 0) {
                if (prefix.prefix_length > longest_match_len) {
                    longest_match_len = prefix.prefix_length;
                    best_match_route = &route;
                }
            }
        }
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

    void withdraw_route(const IpPrefix& prefix, bool verbose = true) {
        if (verbose) {
            std::cout << "Router " << router_id_ << " withdrawing route " 
                      << prefix.network_address << "/" << prefix.prefix_length << std::endl;
        }
        // Remove the route from our own table if it exists
        routing_table_.erase(prefix);
        // withdrawal update to all peers
        UpdateMessage update;
        update.withdrawn_routes.push_back(prefix);

        for (auto const& [peer_ip, peer] : peers_) {
            if (peer.state == SessionState::ESTABLISHED) {
                send_message(peer_ip, update);
            }
        }
    }

    void resend_routes(bool verbose = true) {
        if (verbose) {
            std::cout << "Router " << router_id_ << " re-sending all routes to peers." << std::endl;
        }

        UpdateMessage update;
        for (const auto& [prefix, route] : routing_table_) {
            update.advertised_routes.push_back(route);
        }

        if (!update.advertised_routes.empty()) {
            for (auto const& [peer_ip, peer] : peers_) {
                if (peer.state == SessionState::ESTABLISHED) {
                    // Note: In a real router, you'd re-apply outbound policies here.
                    // For this simulation, a direct resend is sufficient.
                    send_message(peer_ip, update);
                }
            }
        }
    }

private:
    std::string router_id_;
    uint32_t as_number_;
    std::map<std::string, Peer> peers_;
    std::map<IpPrefix, Route> routing_table_;
    std::vector<Header*> inbox_;
    int tick_counter_ = 0;

    const double DIRECT_TRUST_WEIGHT = 0.6;
    const double VOTED_TRUST_WEIGHT = 0.4;
    const double DEFAULT_TRUST = 0.5;

    std::map<std::string, double> direct_trust_values_;
    std::map<std::string, double> voted_trust_values_;
    std::map<std::string, double> total_trust_values_;
    std::map<std::string, std::map<std::string, double>> received_trust_data_;

    double get_trust(const std::string& router_id) {
        if (total_trust_values_.count(router_id)) {
            return total_trust_values_.at(router_id);
        }
        return DEFAULT_TRUST;
    }

    void handle_trust_message(Peer& peer, const TrustMessage& message) {
        received_trust_data_[peer.peer_ip] = message.trust_data;
    }

    void calculate_and_update_trust() {
        for (auto& [target_peer_ip, target_peer] : peers_) {
            double direct_trust = DEFAULT_TRUST;
            if (target_peer.total_interactions > 0) {
                direct_trust = static_cast<double>(target_peer.successful_interactions) / target_peer.total_interactions;
            }
            double total_weighted_vote = 0.0;
            double total_weight = 0.0;
            for (auto const& [voter_peer_ip, voter_peer] : peers_) {
                if (voter_peer_ip == target_peer_ip) continue;
                double voter_trust = get_trust(voter_peer_ip);
                double vote = DEFAULT_TRUST;
                if (received_trust_data_.count(voter_peer_ip) && received_trust_data_[voter_peer_ip].count(target_peer_ip)) {
                    vote = received_trust_data_[voter_peer_ip][target_peer_ip];
                }
                total_weighted_vote += vote * voter_trust;
                total_weight += voter_trust;
            }
            double voted_trust = (total_weight > 0) ? (total_weighted_vote / total_weight) : DEFAULT_TRUST;
            double total_trust = (DIRECT_TRUST_WEIGHT * direct_trust) + (VOTED_TRUST_WEIGHT * voted_trust);
            total_trust = std::max(0.0, std::min(1.0, total_trust)); 
            total_trust_values_[target_peer_ip] = total_trust;
        }
    }

    void send_trust_updates() {
        TrustMessage msg;
        msg.trust_data = this->total_trust_values_;
        for (auto const& [peer_ip, peer] : peers_) {
            if (peer.state == SessionState::ESTABLISHED) {
                send_message(peer_ip, msg);
            }
        }
    }

    void handle_update(Peer& peer, const UpdateMessage& message, bool verbose) {
        if (peer.state != SessionState::ESTABLISHED) return;
        if (verbose) {
            std::cout << router_id_ << " <- " << peer.peer_ip << ": Received UPDATE." << std::endl;
        }
        bool table_changed = false;

        for (const auto& withdrawn_prefix : message.withdrawn_routes) {
        // Check if we have a route for this prefix
        if (routing_table_.count(withdrawn_prefix)) {
            // only remove the route if it came from the peer who is now withdrawing it.
            if (routing_table_.at(withdrawn_prefix).next_hop_ip == peer.peer_ip) {
                routing_table_.erase(withdrawn_prefix);
                table_changed = true; // A withdrawal is a table change
                if (verbose) {
                    std::cout << "    Route to " << withdrawn_prefix.network_address << "/" << withdrawn_prefix.prefix_length 
                              << " withdrawn by " << peer.peer_ip << "." << std::endl;
                }
            }
        }
    }

        for (const auto& new_route_info : message.advertised_routes) {
            Route candidate_route = new_route_info;
            candidate_route.next_hop_ip = peer.peer_ip;

            if (!this->apply_inbound_policies(candidate_route, peer)) {
                if (verbose) {
                    std::cout << "   Route " << candidate_route.prefix.network_address << "/" << candidate_route.prefix.prefix_length 
                              << " denied by inbound policy from " << peer.peer_ip << std::endl;
                }
                continue;
            }

            double next_hop_trust = get_trust(candidate_route.next_hop_ip);
            double effective_local_pref = candidate_route.local_pref * next_hop_trust;

            if (routing_table_.count(candidate_route.prefix) == 0) {
                routing_table_[candidate_route.prefix] = candidate_route;
                table_changed = true;
            } else {
                Route& existing_route = routing_table_.at(candidate_route.prefix);
                double existing_route_trust = get_trust(existing_route.next_hop_ip);
                double existing_effective_local_pref = existing_route.local_pref * existing_route_trust;

                if (effective_local_pref > existing_effective_local_pref) {
                    existing_route = candidate_route;
                    table_changed = true;
                } else if (effective_local_pref == existing_effective_local_pref &&
                           candidate_route.as_path.size() < existing_route.as_path.size()) {
                    existing_route = candidate_route;
                    table_changed = true;
                }
            }
        }

        if (table_changed) {
            if (verbose) {
                std::cout << "   " << router_id_ << "'s routing table changed. Propagating updates." << std::endl;
            }
            for (auto const& [next_peer_ip, next_peer] : peers_) {
                if (next_peer_ip != peer.peer_ip && next_peer.state == SessionState::ESTABLISHED) {
                    UpdateMessage downstream_update;
                    for (const auto& [prefix, route] : routing_table_) {
                        Route new_advertisement = route;
                        new_advertisement.as_path.push_front(this->as_number_);
                        if (!apply_outbound_policies(new_advertisement, next_peer)) {
                            if (verbose) {
                                std::cout << "   Route " << new_advertisement.prefix.network_address << "/" << new_advertisement.prefix.prefix_length 
                                          << " denied by outbound policy to " << next_peer.peer_ip << std::endl;
                            }
                            continue;
                        }
                        downstream_update.advertised_routes.push_back(new_advertisement);
                    }
                    send_message(next_peer_ip, downstream_update);
                }
            }
        }
    }

    bool apply_inbound_policies(Route& route, const Peer& peer) {
        for (const auto& policy : policies) {
            if (policy.direction == PolicyDirection::INBOUND) {
                if (policy.match_peer_ip == peer.peer_ip || policy.match_prefix == route.prefix) {
                    if (policy.action == PolicyAction::DENY) {
                        return false;
                    }
                    else if (policy.action == PolicyAction::SET_LOCAL_PREF) {
                        route.local_pref = policy.action_value;
                    } else if (policy.action == PolicyAction::AS_PATH_PREPEND) {
                        for (int i = 0; i < policy.action_value; ++i) {
                            route.as_path.push_front(this->as_number_);
                        }
                    }
                }
            }
        }
        return true;
    }

    bool apply_outbound_policies(Route& route, const Peer& peer) {
        for (const auto& policy : policies) {
            if (policy.direction == PolicyDirection::OUTBOUND) {
                if (policy.match_peer_ip == peer.peer_ip || policy.match_prefix == route.prefix) {
                    if (policy.action == PolicyAction::DENY) {
                        return false;
                    } else if (policy.action == PolicyAction::SET_LOCAL_PREF) {
                        route.local_pref = policy.action_value;
                    } else if (policy.action == PolicyAction::AS_PATH_PREPEND) {
                        for (int i = 0; i < policy.action_value; ++i) {
                            route.as_path.push_front(this->as_number_);
                        }
                    }
                }
            }
        }
        return true;
    }
};

void Router::process_inbox(bool verbose) {
    for (Header* msg : inbox_) {
        receive_message(msg->from_ip, *msg, verbose);
        delete msg;
    }
    inbox_.clear();
}

void Router::send_message(const std::string& to_ip, Header& message) {
    if (network.count(to_ip)) {
        Router* destination_router = network[to_ip];
        message.from_ip = this->router_id_;

        Header* msg_copy = nullptr;
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
            case MessageType::TRUST_MESSAGE:
                msg_copy = new TrustMessage(*static_cast<TrustMessage*>(&message));
                break;
        }
        if (msg_copy) {
           destination_router->inbox_.push_back(msg_copy);
        }
    }
}

void Router::handle_keepalive(Peer& peer, const KeepaliveMessage& message, bool verbose) {
    peer.successful_interactions++;
    if (peer.state == SessionState::OPEN_SENT) {
        peer.state = SessionState::ESTABLISHED;
        if (verbose) {
            std::cout << "Session ESTABLISHED with " << peer.peer_ip << std::endl;
        }
        UpdateMessage update_for_new_peer;
        for (const auto& [prefix, route] : routing_table_) {
            if (route.next_hop_ip == "0.0.0.0" || route.next_hop_ip == this->router_id_) {
                update_for_new_peer.advertised_routes.push_back(route);
            }
        }
        if (!update_for_new_peer.advertised_routes.empty()) {
            send_message(peer.peer_ip, update_for_new_peer);
        }
    }
}

void Router::handle_open(Peer& peer, const OpenMessage& message, bool verbose) {
    if (verbose) {
        std::cout << router_id_ << " <- " << peer.peer_ip << ": Received OPEN." << std::endl;
    }
    KeepaliveMessage keepalive;
    send_message(peer.peer_ip, keepalive);
    if (peer.state == SessionState::IDLE) {
        OpenMessage open;
        open.router_id = this->router_id_;
        open.as_number = this->as_number_;
        send_message(peer.peer_ip, open);
        peer.state = SessionState::OPEN_SENT;
    }
}

void Router::print_routing_table() {
    std::cout << "\n--- Routing Table for " << router_id_ << " (AS " << as_number_ << ") ---" << std::endl;
    if(routing_table_.empty()) {
        std::cout << "(Table is empty)" << std::endl;
        return;
    }
    std::cout << "Prefix\t\t\tNext Hop\t\tTrust\tAS_PATH" << std::endl;
    std::cout << "-----------------------------------------------------------------------" << std::endl;
    for(const auto& [prefix, route] : routing_table_) {
        double trust = get_trust(route.next_hop_ip);
        std::cout << std::left << std::setw(24) << (prefix.network_address + "/" + std::to_string(prefix.prefix_length))
                  << std::setw(24) << route.next_hop_ip
                  << std::fixed << std::setprecision(3) << std::setw(8) << trust
                  << "[ ";
        for(uint32_t as : route.as_path) {
            std::cout << as << " ";
        }
        std::cout << "]" << std::endl;
    }
    std::cout << "-----------------------------------------------------------------------" << std::endl;
}

void Router::originate_route(const IpPrefix& prefix, bool verbose) {
    if (verbose) {
        std::cout << "Router " << router_id_ << " originating route " 
                  << prefix.network_address << "/" << prefix.prefix_length << std::endl;
    }
    Route new_route;
    new_route.prefix = prefix;
    new_route.next_hop_ip = router_id_;
    new_route.as_path.push_back(as_number_);
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
    std::map<std::string, int> router_as_map;
    while (std::getline(infile, line)) {
        auto comment_pos = line.find('#');
        if (comment_pos != std::string::npos) line = line.substr(0, comment_pos);
        std::istringstream iss(line);
        std::string token;
        if (!(iss >> token)) continue;
        if (token == "[Routers]") { current = ROUTERS; continue; }
        if (token == "[Links]") { current = LINKS; continue; }
        if (current == ROUTERS) {
            std::string router_id = token;
            uint32_t asn;
            if (!(iss >> asn)) continue;
            auto* r = new Router(router_id, asn);
            all_routers.push_back(r);
            Router::network[router_id] = r;
            router_as_map[router_id] = asn;
        } else if (current == LINKS) {
            std::string router1 = token, router2;
            if (!(iss >> router2)) continue;
            uint32_t as2 = router_as_map[router2];
            if (Router::network.count(router1) && Router::network.count(router2)) {
                Router::network[router1]->add_peer(router2, as2);
                Router::network[router2]->add_peer(router1, router_as_map[router1]);
            }
        }
    }
}

void Router::tick(bool verbose) {
    for (auto& [peer_ip, peer] : peers_) {
        peer.total_interactions++;
        if (peer.state == SessionState::IDLE) {
            if (verbose) {
                std::cout << router_id_ << " -> " << peer_ip << ": Sending OPEN." << std::endl;
            }
            OpenMessage open;
            open.router_id = this->router_id_;
            open.as_number = this->as_number_;
            send_message(peer_ip, open);
            peer.state = SessionState::OPEN_SENT;
        } else if (peer.state == SessionState::ESTABLISHED) {
            KeepaliveMessage keepalive;
            send_message(peer_ip, keepalive);
        }
    }
    if (tick_counter_++ % 5 == 0) {
        calculate_and_update_trust();
        send_trust_updates();
    }
}

void Router::print_trust_table() const {
    std::cout << "\n--- Trust Table for " << router_id_ << " (AS " << as_number_ << ") ---" << std::endl;
    if (total_trust_values_.empty()) {
        std::cout << "(Table is empty)" << std::endl;
        return;
    }
    std::cout << "Target Router\t\tTotal Trust" << std::endl;
    std::cout << "------------------------------------------" << std::endl;
    for (const auto& [target_ip, trust_value] : total_trust_values_) {
        std::cout << std::left << std::setw(24) << target_ip
                  << std::fixed << std::setprecision(4) << trust_value << std::endl;
    }
    std::cout << "------------------------------------------" << std::endl;
}

void Router::print_peer_summary() const {
    std::cout << "\n--- BGP Peer Summary for " << router_id_ << " (AS " << as_number_ << ") ---" << std::endl;
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

void print_help() {
    std::cout << "BGP Simulator CLI Commands:\n"
              << "  show ip bgp <router_id>            - Display the BGP routing table for a router.\n"
              << "  show peers <router_id>             - Display the BGP peers and their session status.\n"
              << "  show trust <router_id>             - Display the trust table for a router.\n"
              << "  tick [n]                         - Advance the simulation by 'n' ticks (default is 1).\n"
              << "  neighbor <r_id> <p_ip> remote-as <asn> - Configure a new peer.\n"
              << "  **policy <r_id> [in|out] [permit|deny] prefix <p/l> - Add a policy to a router.**\n"
              << "  announce <r_id> <prefix/len>     - Simulate a prefix hijack from a router.**\n"
              << "  withdraw <r_id> <prefix/len>     - Withdraw route from its original source.\n"
              << "  help                             - Show this help message.\n"
              << "  exit / quit                        - Exit the simulator.\n";
}

// --- CHANGE: Added verbose parameter with default value ---
void run_simulation_ticks(std::vector<Router*>& routers, int count, bool verbose = true) {
    for (int i = 0; i < count; ++i) {
        for(Router* r : routers) {
            r->tick(verbose);
        }
        for(Router* r : routers) {
            r->process_inbox(verbose);
        }
    }
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
    }

    std::cout << "\n--- Initializing Network and Establishing Sessions... ---" << std::endl;
    // --- CHANGE: Run silently ---
    run_simulation_ticks(all_routers, 3, false);
    std::cout << "Done." << std::endl;

    std::cout << "\n--- Originating Routes and Allowing Network to Converge... ---" << std::endl;
    if (!all_routers.empty()) {
        all_routers[0]->originate_route({"10.10.10.0", 24}, true);
    }
    
    std::cout << "\n--- Allowing Trust Protocol to Propagate... ---" << std::endl;
    // --- CHANGE: Run silently ---
    run_simulation_ticks(all_routers, 10, false);
    std::cout << "Done." << std::endl;

    std::cout << "\n\n--- Network converged. Entering interactive CLI. ---" << std::endl;
    print_help(); // This will now print the updated instructions

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
            run_simulation_ticks(all_routers, num_ticks, true);

        } else if (command == "neighbor") {
            if (tokens.size() == 5 && tokens[3] == "remote-as") {
                const std::string& router_id = tokens[1];
                const std::string& peer_ip = tokens[2];
                const std::string& asn_str = tokens[4];

                if (Router::network.count(router_id) == 0) {
                    std::cout << "Error: Router '" << router_id << "' not found." << std::endl;
                    continue;
                }
                try {
                    uint32_t peer_as = std::stoul(asn_str);
                    Router* router = Router::network[router_id];
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
            } else if (tokens.size() == 3 && tokens[1] == "trust") {
                const std::string& router_id = tokens[2];
                if (Router::network.count(router_id)) {
                    Router::network[router_id]->print_trust_table();
                } else {
                    std::cout << "Error: Router '" << router_id << "' not found." << std::endl;
                }
            }
            else {
                std::cout << "Error: Invalid 'show' command. Type 'help' for syntax." << std::endl;
            }
        } else if (command == "policy") {
            if (tokens.size() != 6 || tokens[4] != "prefix") {
                std::cout << "Usage: policy <router_id> [in|out] [permit|deny] prefix <network/len>" << std::endl;
                continue;
            }
            const std::string& router_id = tokens[1];
            if (Router::network.count(router_id) == 0) {
                std::cout << "Error: Router '" << router_id << "' not found." << std::endl;
                continue;
            }
            Router* router = Router::network[router_id];
            Policy new_policy;
            new_policy.rule_name = "cli_policy_" + std::to_string(router->policies.size());

            if (tokens[2] == "in") new_policy.direction = PolicyDirection::INBOUND;
            else if (tokens[2] == "out") new_policy.direction = PolicyDirection::OUTBOUND;
            else { std::cout << "Error: Invalid direction '" << tokens[2] << "'. Use 'in' or 'out'." << std::endl; continue; }
            
            if (tokens[3] == "permit") new_policy.action = PolicyAction::PERMIT;
            else if (tokens[3] == "deny") new_policy.action = PolicyAction::DENY;
            else { std::cout << "Error: Invalid action '" << tokens[3] << "'. Use 'permit' or 'deny'." << std::endl; continue; }

            std::string prefix_str = tokens[5];
            size_t slash_pos = prefix_str.find('/');
            if (slash_pos == std::string::npos) {
                std::cout << "Error: Invalid prefix format. Use address/length (e.g., 10.0.0.0/8)." << std::endl;
                continue;
            }
            try {
                new_policy.match_prefix.network_address = prefix_str.substr(0, slash_pos);
                new_policy.match_prefix.prefix_length = std::stoi(prefix_str.substr(slash_pos + 1));
            } catch (const std::exception& e) {
                std::cout << "Error: Could not parse prefix '" << prefix_str << "'." << std::endl;
                continue;
            }
            new_policy.match_peer_ip = ""; 

            router->add_policy_rule(new_policy);
            std::cout << "Successfully added policy '" << new_policy.rule_name << "' to router " << router_id << "." << std::endl;
        } else if (command == "announce") {
            if (tokens.size() != 3) {
                std::cout << "Usage: announce <router_id> <network/len>" << std::endl;
                continue;
            }

            const std::string& router_id = tokens[1];
            if (Router::network.count(router_id) == 0) {
                std::cout << "Error: Router '" << router_id << "' not found." << std::endl;
                continue;
            }
            Router* router = Router::network[router_id];
            
            std::string prefix_str = tokens[2];
            size_t slash_pos = prefix_str.find('/');
            if (slash_pos == std::string::npos) {
                std::cout << "Error: Invalid prefix format. Use address/length (e.g., 10.0.0.0/8)." << std::endl;
                continue;
            }
            try {
                IpPrefix false_prefix;
                false_prefix.network_address = prefix_str.substr(0, slash_pos);
                false_prefix.prefix_length = std::stoi(prefix_str.substr(slash_pos + 1));
                
                std::cout << "ATTACK: Triggering false announcement for " << prefix_str 
                          << " from router " << router_id << "." << std::endl;
                router->originate_route(false_prefix, true);

            } catch (const std::exception& e) {
                std::cout << "Error: Could not parse prefix '" << prefix_str << "'." << std::endl;
                continue;
            }
        }  else if (command == "withdraw") {
            if (tokens.size() != 3) {
                std::cout << "Usage: withdraw <router_id> <network/len>" << std::endl;
                continue;
            }

            const std::string& router_id = tokens[1];
            if (Router::network.count(router_id) == 0) {
                std::cout << "Error: Router '" << router_id << "' not found." << std::endl;
                continue;
            }
            Router* router = Router::network[router_id];
            
            std::string prefix_str = tokens[2];
            size_t slash_pos = prefix_str.find('/');
            if (slash_pos == std::string::npos) {
                std::cout << "Error: Invalid prefix format." << std::endl;
                continue;
            }
            try {
                IpPrefix prefix_to_withdraw;
                prefix_to_withdraw.network_address = prefix_str.substr(0, slash_pos);
                prefix_to_withdraw.prefix_length = std::stoi(prefix_str.substr(slash_pos + 1));
                
                router->withdraw_route(prefix_to_withdraw, true);

            } catch (const std::exception& e) {
                std::cout << "Error: Could not parse prefix '" << prefix_str << "'." << std::endl;
                continue;
            }
        
        } else if (command == "resend-routes") {
            if (tokens.size() != 2) {
                std::cout << "Usage: resend-routes <router_id>" << std::endl;
                continue;
            }
            const std::string& router_id = tokens[1];
            if (Router::network.count(router_id) == 0) {
                std::cout << "Error: Router '" << router_id << "' not found." << std::endl;
                continue;
            }
            Router::network[router_id]->resend_routes();
        } else {
            std::cout << "Error: Unknown command '" << command << "'. Type 'help' for available commands." << std::endl;
        }
    }

    // Cleanup
    for (Router* r : all_routers) {
        delete r;
    }
    all_routers.clear();

    return 0;
}

std::map<std::string, Router*> Router::network;
