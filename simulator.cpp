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
#include <set>

struct IpPacket {
    std::vector<bool> bits; // The entire packet as a sequence of bits
    std::string payload; // The payload as a string
    std::string source_ip;
    std::string destination_ip;
};

struct IpPrefix {
    std::string network_address;
    uint8_t prefix_length;

    std::string to_string() const {
        return network_address + "/" + std::to_string(prefix_length);
    }

    bool operator==(const IpPrefix& other) const {
        return network_address == other.network_address && prefix_length == other.prefix_length;
    }

    bool operator<(const IpPrefix& other) const {
        if (network_address != other.network_address)
            return network_address < other.network_address;
        return prefix_length < other.prefix_length;
    }

    bool is_default() const {
        return network_address.empty() && prefix_length == 0;
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

    bool operator==(const Route& other) const {
        return prefix == other.prefix
            && next_hop_ip == other.next_hop_ip
            && as_path == other.as_path
            && local_pref == other.local_pref
            && med == other.med
            && origin == other.origin;
    }
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

    const std::string& get_router_id() const { return router_id_; }
    uint32_t get_as_number() const { return as_number_; }

    void print_peer_summary() const;
    void print_routing_table();
    void tick(bool verbose);
    void originate_route(const IpPrefix& prefix, bool verbose = true);
    void handle_open(Peer& peer, const OpenMessage& message, bool verbose);
    void handle_keepalive(Peer& peer, const KeepaliveMessage& message, bool verbose);
    void process_inbox(bool verbose); 
    void send_message(const std::string& to_ip, Header& message);
    bool is_active() const { return is_active_; }
    static std::map<std::string, Router*> network;
    std::vector<Policy> policies;
    void print_trust_table() const;
    bool has_peer(const std::string& peer_ip) const {
        return peers_.find(peer_ip) != peers_.end();
    }


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

    void shutdown() {
        std::cout << "Shutting down router " << router_id_ << "." << std::endl;
        is_active_ = false;
        
        // Tear down all active BGP sessions
        for (auto& [peer_ip, peer] : peers_) {
            if (peer.state == SessionState::ESTABLISHED) {
                NotificationMessage notification;
                send_message(peer_ip, notification); // Inform peer of shutdown
                peer.state = SessionState::IDLE;
            }
        }
    }

    void startup() {
        std::cout << "Starting up router " << router_id_ << "." << std::endl;
        is_active_ = true;
        // The tick() method will automatically begin re-establishing sessions.
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

        // Remove all routes learned from this peer ---
        {
            std::vector<IpPrefix> prefixes_to_remove;
            for (const auto& [prefix, route] : routing_table_) {
                if (route.next_hop_ip == peer.peer_ip) {
                    prefixes_to_remove.push_back(prefix);
                }
            }

            if (!prefixes_to_remove.empty()) {
                if (verbose) {
                    std::cout << "    " << router_id_ << ": Removing " << prefixes_to_remove.size() << " stale route(s) from peer " << peer.peer_ip << "." << std::endl;
                }
                for (const auto& prefix : prefixes_to_remove) {
                    routing_table_.erase(prefix);
                }
                // For this project, simply removing the routes is sufficient.
            }
        }
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

    if (rule.direction == PolicyDirection::OUTBOUND && rule.action == PolicyAction::DENY) {
  
        if (rule.match_peer_ip.empty()) {
            std::cout << "Applying general outbound deny for " << rule.match_prefix.to_string() 
                      << ". Withdrawing from ALL peers." << std::endl;
            
            send_withdrawal_all(rule.match_prefix);

        } else {
            
            std::cout << "Applying specific outbound deny for " << rule.match_prefix.to_string() 
                      << " to peer " << rule.match_peer_ip << "." << std::endl;
            
            send_withdrawal_peer(rule.match_prefix, rule.match_peer_ip);
        }

    } else if (rule.direction == PolicyDirection::INBOUND && rule.action == PolicyAction::DENY) {
    std::cout << "Applying new inbound deny for " << rule.match_prefix.to_string() 
              << ". Re-evaluating BGP table." << std::endl;
    
    if (bgp_table_.count(rule.match_prefix)) {
        bool path_changed = false;
        
        // Iterate over all peers that gave us this route
        for (auto it = bgp_table_[rule.match_prefix].begin(); it != bgp_table_[rule.match_prefix].end(); /* no increment */) {
            
            std::string peer_ip = it->first;
            
            // Does
            bool peer_matches = rule.match_peer_ip.empty() || (rule.match_peer_ip == peer_ip);

            if (peer_matches) {
                // Yes, this existing route is now denied. Erase it.
                it = bgp_table_[rule.match_prefix].erase(it);
                path_changed = true;
                std::cout << "   Removing existing route from peer " << peer_ip << std::endl;
            } else {
                ++it;
            }
        }

        if (path_changed) {
            // The old best path might have been removed. Find the new best one.
            find_and_install_best_path(rule.match_prefix);
        }
    }
}
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

    void add_route_reflector_client(const std::string& peer_ip) {
        // Use the private 'peers_' member
        if (peers_.count(peer_ip)) {
            // Use the private 'as_number_' member
            if (peers_.at(peer_ip).peer_as == this->as_number_) {
                std::cout << "   Configuring peer " << peer_ip << " as a route-reflector-client." << std::endl;
                // Use the new private 'route_reflector_clients_' member
                route_reflector_clients_.insert(peer_ip);
            } else {
                std::cout << "   Error: Peer " << peer_ip << " is an eBGP peer. Cannot be a client." << std::endl;
            }
        } else {
            // Use the private 'router_id_' member
            std::cout << "   Error: Peer " << peer_ip << " not found for router " << router_id_ << "." << std::endl;
        }
    }

private:
    std::string router_id_;
    uint32_t as_number_;
    std::map<std::string, Peer> peers_;
    std::set<std::string> route_reflector_clients_; // New member to track route-reflector clients
    std::map<IpPrefix, std::map<std::string, Route>> bgp_table_;
    std::map<IpPrefix, Route> routing_table_;
    std::vector<Header*> inbox_;
    int tick_counter_ = 0;
    bool is_active_ = true;

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

    bool find_and_install_best_path(const IpPrefix& prefix) {
    if (bgp_table_.count(prefix) == 0 || bgp_table_[prefix].empty()) { 
        if (routing_table_.count(prefix)) {
            routing_table_.erase(prefix);
            return true; // The table changed
        }
        return false;
    }
    // Find the best route among all candidates
    Route* best_route = nullptr;
    const std::map<std::string, Route>& candidates = bgp_table_[prefix];

    for (const auto& [peer_ip, route] : candidates) {
        if (best_route == nullptr) {
            best_route = new Route(route); // Copy the first route as the current best
        } else {
            double new_trust = get_trust(route.next_hop_ip);
            double new_pref = route.local_pref * new_trust;
            
            double old_trust = get_trust(best_route->next_hop_ip);
            double old_pref = best_route->local_pref * old_trust;
            
            if (new_pref > old_pref) {
                *best_route = route; // Found a better route
            } else if (new_pref == old_pref && route.as_path.size() < best_route->as_path.size()) {
                *best_route = route; // Found a better route
            }
        }
    }
    bool changed = false;
    if (routing_table_.count(prefix) == 0 || !(routing_table_[prefix] == *best_route)) {
        routing_table_[prefix] = *best_route;
        changed = true;
    }
    
    delete best_route;
    return changed;
}

    void handle_update(Peer& peer, const UpdateMessage& message, bool verbose) {
        if (peer.state != SessionState::ESTABLISHED) return;
        if (verbose) {
            std::cout << router_id_ << " <- " << peer.peer_ip << ": Received UPDATE." << std::endl;
        }
        bool table_changed = false;

        for (const auto& withdrawn_prefix : message.withdrawn_routes) {
if (bgp_table_.count(withdrawn_prefix)) {
        if (bgp_table_[withdrawn_prefix].erase(peer.peer_ip) > 0) {
            table_changed = true;
            if (verbose) {
                std::cout << "    Route to " << withdrawn_prefix.network_address << "/" << static_cast<int>(withdrawn_prefix.prefix_length)
                          << " from " << peer.peer_ip << " removed from BGP table." << std::endl;
            }
            find_and_install_best_path(withdrawn_prefix);
        }
    }
}

for (const auto& new_route_info : message.advertised_routes) {

    if (peer.peer_as != this->as_number_) {
                bool loop_detected = false;
                for (uint32_t asn_in_path : new_route_info.as_path) {
                    if (asn_in_path == this->as_number_) {
                        loop_detected = true;
                        break;
                    }
                }
                
                if (loop_detected) {
                    if (verbose) {
                        std::cout << "   Route " << new_route_info.prefix.network_address << "/" 
                                  << static_cast<int>(new_route_info.prefix.prefix_length) 
                                  << " REJECTED from " << peer.peer_ip << ": BGP Loop detected." << std::endl;
                    }
                    continue; // Skip (reject) this route
                }
            }

            Route candidate_route = new_route_info;
            
            if (peer.peer_as != this->as_number_) {
                candidate_route.next_hop_ip = peer.peer_ip;
                candidate_route.as_path.push_front(peer.peer_as);
            }

            if (!this->apply_inbound_policies(candidate_route, peer)) {
                if (verbose) {
                    std::cout << "   Route " << candidate_route.prefix.network_address << "/" 
                              << static_cast<int>(candidate_route.prefix.prefix_length) 
                              << " denied by inbound policy from " << peer.peer_ip << std::endl;
                }
                
                if (bgp_table_.count(candidate_route.prefix) && 
                    bgp_table_[candidate_route.prefix].count(peer.peer_ip)) 
                {
                    bgp_table_[candidate_route.prefix].erase(peer.peer_ip);
                    if (verbose) {
                        std::cout << "   Removing stale route from BGP table due to new deny policy." << std::endl;
                    }
                    if (find_and_install_best_path(candidate_route.prefix)) {
                        table_changed = true;
                    }
                }
                
                continue;
            }

            bgp_table_[candidate_route.prefix][peer.peer_ip] = candidate_route;

            if (verbose) {
                 std::cout << "   Route " << candidate_route.prefix.network_address << "/" 
                           << static_cast<int>(candidate_route.prefix.prefix_length)
                           << " from " << peer.peer_ip << " accepted into BGP table." << std::endl;
            }

            bool best_path_was_updated = find_and_install_best_path(candidate_route.prefix);

            if (best_path_was_updated) {
                table_changed = true;
                if (verbose) {
                    std::cout << "   New best path for " << candidate_route.prefix.network_address << "/" 
                              << static_cast<int>(candidate_route.prefix.prefix_length)
                              << " installed." << std::endl;
                }
            }
        }

     if (table_changed) {
            if (verbose) {
                std::cout << "   " << router_id_ << "'s routing table changed. Propagating updates." << std::endl;
            }
            if (route_reflector_clients_.empty()) 
            {
                // STANDARD BGP ROUTER (Not an RR)
                // We obey the iBGP Split-Horizon rule.
                
                for (auto const& [next_peer_ip, next_peer] : peers_) {
                    if (next_peer_ip == peer.peer_ip || next_peer.state != SessionState::ESTABLISHED) {
                        continue;
                    }

                    // iBGP Split Horizon Rule Check
                    // (Don't advertise a route from an iBGP peer to another iBGP peer)
                    bool source_is_ibgp = (peer.peer_as == this->as_number_);
                    bool dest_is_ibgp = (next_peer.peer_as == this->as_number_);
                    
                    if (source_is_ibgp && dest_is_ibgp) {
                        // This is the split-horizon rule. Don't propagate.
                        if (verbose) {
                             std::cout << "   Skipping peer " << next_peer_ip << " (iBGP Split Horizon)." << std::endl;
                        }
                        continue; 
                    }
                    
                    // This peer is OK to send to (either eBGP, or from eBGP to iBGP)
                    UpdateMessage downstream_update;

                    for (const auto& withdrawn_prefix : message.withdrawn_routes) {
                         // Only propagate withdrawals if our best path was affected
                        if (!routing_table_.count(withdrawn_prefix)) {
                             downstream_update.withdrawn_routes.push_back(withdrawn_prefix);
                        }
                    }

                    // Propagate advertisements
                    for (const auto& [prefix, route] : routing_table_) {
                        // We only need to advertise the routes that just changed.
                        // A simple way is to check if the new best route is the one from 'peer'.
                        if (bgp_table_.count(prefix) && bgp_table_.at(prefix).count(peer.peer_ip)) {
                             if(routing_table_.at(prefix).next_hop_ip == peer.peer_ip) {
                                Route new_advertisement = route;
                                if (next_peer.peer_as != this->as_number_) {
                                    new_advertisement.as_path.push_front(this->as_number_);
                                }
                                if (apply_outbound_policies(new_advertisement, next_peer)) {
                                    downstream_update.advertised_routes.push_back(new_advertisement);
                                }
                             }
                        }
                    }

                    if (!downstream_update.advertised_routes.empty() || !downstream_update.withdrawn_routes.empty()) {
                        send_message(next_peer_ip, downstream_update);
                    }
                }
            } 
            else 
            {
                // ROUTE REFLECTOR (RR)

                for (auto const& [next_peer_ip, next_peer] : peers_) {
                    if (next_peer_ip == peer.peer_ip || next_peer.state != SessionState::ESTABLISHED) {
                        continue;
                    }

                    UpdateMessage downstream_update;
                    
                    // Propagate withdrawals
                    for (const auto& withdrawn_prefix : message.withdrawn_routes) {
                        if (!routing_table_.count(withdrawn_prefix)) {
                             downstream_update.withdrawn_routes.push_back(withdrawn_prefix);
                        }
                    }

                    bool sending_to_client = route_reflector_clients_.count(next_peer_ip);
                    bool sending_to_ibgp = (next_peer.peer_as == this->as_number_);
                    bool sending_to_ebgp = !sending_to_ibgp;

                    // Iterate over *all* best routes (not just the changed ones)
                    // This is simpler and more robust for RR logic
                    for (const auto& [prefix, route] : routing_table_) {

                        // --- Find the *source* of this best route ---
                        bool best_route_originated_by_us = (route.next_hop_ip == this->router_id_);
                        bool best_route_from_ebgp = false;
                        bool best_route_from_client = false;
                        bool best_route_from_non_client_ibgp = false;

                        if (!best_route_originated_by_us) {
                            // Find the peer who gave us this best path
                            std::string best_path_source_peer_ip = "";
                            if (bgp_table_.count(prefix)) {
                                for (auto const& [src_ip, peer_route] : bgp_table_.at(prefix)) {
                                    if (peer_route.next_hop_ip == route.next_hop_ip && peer_route.as_path == route.as_path) {
                                        best_path_source_peer_ip = src_ip;
                                        break;
                                    }
                                }
                            }
                            
                            if (peers_.count(best_path_source_peer_ip)) {
                                Peer& source_peer = peers_.at(best_path_source_peer_ip);
                                if (source_peer.peer_as != this->as_number_) {
                                    best_route_from_ebgp = true;
                                } else {
                                    if (route_reflector_clients_.count(best_path_source_peer_ip)) {
                                        best_route_from_client = true;
                                    } else {
                                        best_route_from_non_client_ibgp = true;
                                    }
                                }
                            } else if (!best_path_source_peer_ip.empty()) {
                                // Peer isn't in our list? Must be eBGP.
                                best_route_from_ebgp = true;
                            }
                        }

                        Route new_advertisement = route;
                        if (sending_to_ebgp) {
                            new_advertisement.as_path.push_front(this->as_number_);
                        }
                        if (!apply_outbound_policies(new_advertisement, next_peer)) {
                            continue; // Denied by outbound policy
                        }

                        if (sending_to_ebgp) {
                            // Always send best routes to eBGP peers
                            downstream_update.advertised_routes.push_back(new_advertisement);
                        } else { 
                            // Sending to an iBGP peer (client or non-client)
                            if (best_route_from_client) {
                                // Route from client -> Reflect to ALL (clients and non-clients)
                                downstream_update.advertised_routes.push_back(new_advertisement);
                            } else if (best_route_from_non_client_ibgp) {
                                // Route from non-client iBGP -> Reflect to CLIENTS ONLY
                                if (sending_to_client) {
                                    downstream_update.advertised_routes.push_back(new_advertisement);
                                }
                            } else { // best_route_from_ebgp or best_route_originated_by_us
                                // Route from eBGP or originated by us -> Reflect to ALL iBGP peers
                                downstream_update.advertised_routes.push_back(new_advertisement);
                            }
                        }
                    }
                    if (!downstream_update.advertised_routes.empty() || !downstream_update.withdrawn_routes.empty()) {
                        send_message(next_peer_ip, downstream_update);
                    }
                }
            }
        }
    }

    bool apply_inbound_policies(Route& route, const Peer& peer) {
        for (const auto& policy : policies) {
        bool peer_matches = policy.match_peer_ip.empty() || (policy.match_peer_ip == peer.peer_ip);

        if (policy.direction == PolicyDirection::INBOUND) {
            if (peer_matches && policy.match_prefix == route.prefix) {
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
            
            // Check if the policy's peer matches (or if the policy doesn't care about the peer)
            bool peer_matches = policy.match_peer_ip.empty() || policy.match_peer_ip == peer.peer_ip;
            bool prefix_matches = policy.match_prefix.is_default() || policy.match_prefix == route.prefix;

            if (peer_matches && prefix_matches) {

                if (policy.action == PolicyAction::DENY) {
                    return false; // Stop processing and deny the route
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

  void send_withdrawal_all(const IpPrefix& prefix) {
    std::cout << "Router " << router_id_ << " withdrawing " << prefix.to_string() 
              << " from ALL peers." << std::endl;

    UpdateMessage update;
    update.withdrawn_routes.push_back(prefix);

    for (auto const& [peer_ip, peer] : peers_) {
        if (peer.state == SessionState::ESTABLISHED) {
            send_message(peer_ip, update);
        }
    }
}

void send_withdrawal_peer(const IpPrefix& prefix, const std::string& target_peer_ip) {
    std::cout << "Router " << router_id_ << " withdrawing " << prefix.to_string() 
              << " from peer " << target_peer_ip << std::endl;
    UpdateMessage update;
    update.withdrawn_routes.push_back(prefix);
    // Only send to the one peer affected by the outbound policy
    if (peers_.count(target_peer_ip) && peers_.at(target_peer_ip).state == SessionState::ESTABLISHED) {
        send_message(target_peer_ip, update);
    }
}
};

void Router::process_inbox(bool verbose) {
    if (!is_active_) {
        return; // Don't process messages if shut down
    }
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
        // Send the entire routing table to the new peer.
        UpdateMessage update_for_new_peer;
        for (const auto& [prefix, route] : routing_table_) {
            // it will advertise ALL best paths, not just self-originated ones.
            update_for_new_peer.advertised_routes.push_back(route);
        }
        
        if (!update_for_new_peer.advertised_routes.empty()) {
            if (verbose) {
                 std::cout << "    " << router_id_ << " -> " << peer.peer_ip 
                           << ": Sending initial routing table (" 
                           << update_for_new_peer.advertised_routes.size() << " routes)." << std::endl;
            }
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

void load_topology(const std::string& filename,
                   std::vector<Router*>& all_routers,
                   std::map<uint32_t, IpPrefix>& as_prefixes) // Added as_prefixes map
{
    std::ifstream infile(filename);
    if (!infile.is_open()) {
        std::cerr << "Error: Could not open topology file: " << filename << std::endl;
        return;
    }

    std::string line;
    // Added PREFIXES state
    enum Section { NONE, ROUTERS, LINKS, PREFIXES }; 
    Section current = NONE;
    
    // Map to temporarily store router_id -> asn mapping, useful for [Links] section
    std::map<std::string, uint32_t> router_as_map;

    while (std::getline(infile, line)) {
        // Strip comments
        auto comment_pos = line.find('#');
        if (comment_pos != std::string::npos) {
            line = line.substr(0, comment_pos);
        }
        std::istringstream iss(line);
        std::string token;
        // Skip empty or whitespace-only lines
        if (!(iss >> token)) {
            continue; 
        }
        if (token == "[Routers]") { current = ROUTERS; continue; }
        if (token == "[Links]") { current = LINKS; continue; }
        // Check for [Prefixes] section
        if (token == "[Prefixes]") { current = PREFIXES; continue; }
        if (current == ROUTERS) {
            std::string router_id = token;
            uint32_t asn;
            if (!(iss >> asn)) {
                std::cerr << "Warning: Malformed [Routers] line: " << line << std::endl;
                continue;
            }
            Router* r = new Router(router_id, asn);
            all_routers.push_back(r);
            Router::network[router_id] = r;
            router_as_map[router_id] = asn;

        } else if (current == LINKS) {
            std::string router1_id = token;
            std::string router2_id;
            if (!(iss >> router2_id)) {
                std::cerr << "Warning: Malformed [Links] line: " << line << std::endl;
                continue;
            }

            // Ensure both routers exist before adding peers
            if (Router::network.count(router1_id) && Router::network.count(router2_id)) {
                Router::network[router1_id]->add_peer(router2_id, router_as_map[router2_id]);
                Router::network[router2_id]->add_peer(router1_id, router_as_map[router1_id]);
            } else {
                std::cerr << "Warning: Skipping link for unknown router: " << line << std::endl;
            }
        
        // Handle [Prefixes]
        } else if (current == PREFIXES) {
            // Token is the AS Number (e.g., 65001)
            uint32_t asn = static_cast<uint32_t>(std::stoul(token));
            
            std::string prefix_str; // e.g., "172.16.1.0/24"
            if (!(iss >> prefix_str)) {
                std::cerr << "Warning: Malformed [Prefixes] line: " << line << std::endl;
                continue;
            }

            auto slash_pos = prefix_str.find('/');
            if (slash_pos == std::string::npos) {
                std::cerr << "Warning: Prefix missing '/' in line: " << line << std::endl;
                continue;
            }

            // Split the string into address and length
            std::string net_addr = prefix_str.substr(0, slash_pos);
            std::string len_str = prefix_str.substr(slash_pos + 1);

            try {
                // Create the prefix object
                IpPrefix prefix;
                prefix.network_address = net_addr;
                prefix.prefix_length = static_cast<uint8_t>(std::stoi(len_str)); // stoi requires <string>

                // Store in the map
                as_prefixes[asn] = prefix;
            } catch (const std::exception& e) {
                std::cerr << "Warning: Invalid prefix length in line: " << line << " (" << e.what() << ")" << std::endl;
            }
        }
    }
}

void Router::tick(bool verbose) {
    if (!is_active_) {
    return; // Don't process anything if shut down
}
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
              << "  policy <r_id> [in|out] [permit|deny] prefix <p/l> - Add a policy to a router.\n"
              << "  announce <r_id> <prefix/len>     - Simulate a prefix hijack from a router.**\n"
              << "  withdraw <r_id> <prefix/len>     - Withdraw route from its original source.\n"
              << "  shutdown <router_id>            - Shut down a router and its BGP sessions.\n"
              << "  startup <router_id>             - Start up a previously shut down router.\n"
              << "  help                             - Show this help message.\n"
              << "  exit / quit                        - Exit the simulator.\n";
}

// verbose parameter with default value ---
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
    std::map<uint32_t, IpPrefix> as_prefixes;
    if (!topology_file.empty()) {
        load_topology(topology_file, all_routers, as_prefixes);
    } else {
        std::cout << "--- BGP Simulator Startup (Hardcoded Topology) ---" << std::endl;
    }

    std::cout << "\n--- Initializing Network and Establishing Sessions... ---" << std::endl;

    run_simulation_ticks(all_routers, 3, false);
    std::cout << "Done." << std::endl;

std::cout << "\n--- Originating Routes from Each AS... ---" << std::endl;
    
    // A set to track which ASes have already originated their prefix
    std::set<uint32_t> originated_ases;

    for (Router* router : all_routers) {
        uint32_t as_num = router->get_as_number();

        // Only originate once per AS
        if (originated_ases.find(as_num) == originated_ases.end()) {
            
            // Look up the prefix for this AS in the map populated from the .conf file
            auto it = as_prefixes.find(as_num);
            
            if (it != as_prefixes.end()) {
                // Found a prefix for this AS
                IpPrefix prefix_to_originate = it->second;

                std::cout << "Router " << router->get_router_id()
                          << " (AS " << as_num << ") is originating "
                          << prefix_to_originate.network_address << "/" 
                          << static_cast<int>(prefix_to_originate.prefix_length) << std::endl;

                router->originate_route(prefix_to_originate, true);

            } else {
                // No prefix was defined for this AS in the [Prefixes] section
                std::cout << "Warning: No [Prefixes] entry found for AS " << as_num
                          << ". It will not originate any routes." << std::endl;
            }
            originated_ases.insert(as_num);
        }
    }
    
    std::cout << "\n--- Allowing Trust Protocol to Propagate... ---" << std::endl;
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
            } else if (tokens.size() == 4 && tokens[3] == "route-reflector-client") {
                const std::string& router_id = tokens[1];
                const std::string& peer_ip = tokens[2];

                if (Router::network.count(router_id) == 0) {
                    std::cout << "Error: Router '" << router_id << "' not found." << std::endl;
                    continue;
                }
                
                Router* router = Router::network[router_id];
                
                if (!router->has_peer(peer_ip)) { 
                     std::cout << "Error: Peer " << peer_ip << " is not a configured neighbor on " << router_id << "." << std::endl;
                     continue;
                }
                
                // Call the new method we added
                router->add_route_reflector_client(peer_ip);
            
            } else {
                std::cout << "Usage: neighbor <router_id> <peer_ip> remote-as <asn>" << std::endl;
                std::cout << "   or: neighbor <router_id> <peer_ip> route-reflector-client" << std::endl;
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
        } else if (command == "shutdown" && tokens.size() == 2) {
            const std::string& router_id = tokens[1];
            if (Router::network.count(router_id)) {
                Router::network[router_id]->shutdown();
            } else {
                std::cout << "Error: Router '" << router_id << "' not found." << std::endl;
            }
        } else if (command == "startup" && tokens.size() == 2) {
            const std::string& router_id = tokens[1];
            if (Router::network.count(router_id)) {
                Router::network[router_id]->startup();
            } else {
                std::cout << "Error: Router '" << router_id << "' not found." << std::endl;
            }
        // --- The closing brace was moved here ---
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
