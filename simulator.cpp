#include <iostream>
#include <vector>
#include <string>
#include <list> // For AS_PATH
#include <map>
#include <memory> // For smart pointers

// IpPacket struct definition
struct IpPacket {
    std::string destination_ip;
    std::string source_ip;
    std::string payload;
};


struct IpPrefix
{
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

struct Route
{
    IpPrefix prefix;
    std::string next_hop_ip;
    std::list<int> as_path; // AS_PATH represented as a list of AS numbers
    int local_pref;
    int med;
    OriginType origin;
};

// possible states a BGP peering session can be in
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

enum class OriginType {
    IGP = 0,
    EGP = 1,
    INCOMPLETE = 2
};

struct Header
{
    MessageType type;
};

struct KeepaliveMessage : public Header
{
    KeepaliveMessage() { type = MessageType::KEEPALIVE; }
};

struct NotificationMessage : public Header
{
    NotificationMessage() { type = MessageType::NOTIFICATION; }
    int error_code;
};

struct OpenMessage : public Header
{
    OpenMessage() { type = MessageType::OPEN; }
    std::string router_id;
    int as_number;
};

struct UpdateMessage : public Header
{
    UpdateMessage() { type = MessageType::UPDATE; }
    std::vector<Route> advertised_routes;
    std::vector<IpPrefix> withdrawn_routes;
};

// Forward declarations
class Router;

// each peer has its own state and is associated with a local router
struct Peer
{
    std::string peer_ip;
    int peer_as;
    SessionState state;
    Router* local_router;

    Peer(const std::string& ip, int as, Router* router)
        : peer_ip(ip), peer_as(as), state(SessionState::IDLE), local_router(router) {}
};

class Router
{
public:
    std::string router_id;
    int as_number;
    static std::map<std::string, Router*> network;

    Router(const std::string& id, int as_num) : router_id(id), as_number(as_num) {
        network[id] = this;
    }
    void receive_message(Peer& peer, const Header& message);
    void add_peer(const std::string& ip, int as) {
        peers.emplace(ip, Peer(ip, as, this));
    }

    // Originate a route from this router
    void originate_route(const IpPrefix& prefix) {
        std::cout << "Router " << router_id << " originating route " 
                  << prefix.network_address << "/" << prefix.prefix_length << std::endl;
                  Route new_route;
                    new_route.prefix = prefix;
                    new_route.next_hop_ip = router_id;
                    new_route.as_path.push_back(this->as_number);
                    new_route.origin = OriginType::IGP;

                    routing_table[prefix] = new_route;

                    UpdateMessage update;
                    update.advertised_routes.push_back(new_route);
                    for(auto const& [peer_ip, peer] : peers) {
                        if(peer.state == SessionState::ESTABLISHED) {
                            send_message(peer_ip, update);
                        }
                    }
    }

    // Proactive actions: initiating connections, sending keepalives
void tick() {
        for (auto& [peer_ip, peer] : peers) {
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

      void receive_message(const std::string& from_ip, const Header& message) {
        Peer& peer = peers.at(from_ip);
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

      void forward_packet(const IpPacket& packet) {
        std::cout << "\n📦 " << router_id << ": Received packet for destination " << packet.destination_ip << std::endl;

        const Route* best_match_route = nullptr;
        int longest_match_len = -1;

        for (const auto& [prefix, route] : routing_table) {
            // Simple string-based check for Longest Prefix Match
            if (packet.destination_ip.rfind(prefix.network_address, 0) == 0) {
                if (prefix.prefix_length > longest_match_len) {
                    longest_match_len = prefix.prefix_length;
                    best_match_route = &route;
                }
            }
        }

        if (best_match_route) {
            std::cout << "  ✅ Match found for prefix " << best_match_route->prefix.network_address << "/" << best_match_route->prefix.prefix_length << "." << std::endl;
            std::cout << "  ➡️ Forwarding packet to next hop: " << best_match_route->next_hop_ip << std::endl;
        } else {
            std::cout << "  ❌ No route found. Packet dropped." << std::endl;
        }
    }

  void print_routing_table() {
        std::cout << "\n--- Routing Table for " << router_id << " (AS " << as_number << ") ---" << std::endl;
        if(routing_table.empty()) {
            std::cout << "(Table is empty)" << std::endl;
            return;
        }
        for(const auto& [prefix, route] : routing_table) {
            std::cout << "  " << prefix.network_address << "/" << prefix.prefix_length 
                      << " -> next-hop: " << route.next_hop_ip
                      << ", AS_PATH: [ ";
            for(int as : route.as_path) {
                std::cout << as << " ";
            }
            std::cout << "]" << std::endl;
        }
        std::cout << "------------------------------------------" << std::endl;
    }

private:
    std::string router_id;
    int as_number;
    std::map<std::string, Peer> peers; // Keyed by peer IP
    std::map<IpPrefix, Route> routing_table; // for the routing table, each IpPrefix key represents a network prefix (address + length)

         void send_message(const std::string& to_ip, const Header& message) {
        if (network.count(to_ip)) {
            network[to_ip]->receive_message(this->router_id, message);
        }
    }

    void handle_open(Peer& peer, const OpenMessage& message) {
        std::cout << router_id << " <- " << peer.peer_ip << ": Received OPEN." << std::endl;
        if (peer.state == SessionState::OPEN_SENT) {
            std::cout << "   🤝 Session ESTABLISHED with " << peer.peer_ip << std::endl;
            peer.state = SessionState::ESTABLISHED;
            KeepaliveMessage keepalive;
            send_message(peer.peer_ip, keepalive);

            // Now that we're connected, advertise our own routes
            if(!routing_table.empty()){
                UpdateMessage update_for_new_peer;
                for(const auto& [prefix, route] : routing_table) {
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

            // BGP decision process
            if (routing_table.count(candidate_route.prefix) == 0) {
                // If we have no route, we accept this one
                routing_table[candidate_route.prefix] = candidate_route;
                table_changed = true;
            } else {
                // If we have a route, compare AS_PATH length (shorter is better)
                Route& existing_route = routing_table.at(candidate_route.prefix);
                if (candidate_route.as_path.size() < existing_route.as_path.size()) {
                    existing_route = candidate_route;
                    table_changed = true;
                }
            }
        }

        if (table_changed) {
            std::cout << "   " << router_id << "'s routing table changed. Propagating updates." << std::endl;
            // Propagate the best routes to our other peers
            for (auto const& [next_peer_ip, next_peer] : peers) {
                if (next_peer_ip != peer.peer_ip && next_peer.state == SessionState::ESTABLISHED) {
                    UpdateMessage downstream_update;
                    for (const auto& [prefix, route] : routing_table) {
                        Route new_advertisement = route;
                        new_advertisement.as_path.push_front(this->as_number); // Prepend our AS
                        downstream_update.advertised_routes.push_back(new_advertisement);
                    }
                    send_message(next_peer_ip, downstream_update);
                }
            }
        }
    }
};

int main() {
    std::cout << "--- BGP Simulator Startup ---" << std::endl;

    // Routers for the simulation
    Router r1("1.1.1.1", 100);
    Router r2("2.2.2.2", 200);
    Router r3("3.3.3.3", 300);

    // Topology (peering)
    r1.add_peer("2.2.2.2", 200);
    r2.add_peer("1.1.1.1", 100);
    r2.add_peer("3.3.3.3", 300);
    r3.add_peer("2.2.2.2", 200);

    // Simulation ticks to establish sessions
    std::cout << "\n--- Establishing BGP Sessions ---" << std::endl;
    for (int i = 0; i < 2; ++i) {
        std::cout << "\n--- Tick " << i + 1 << " ---" << std::endl;
        r1.tick();
        r2.tick();
        r3.tick();
    }
    
    // A router originates a route
    std::cout << "\n--- Route Origination and Propagation ---" << std::endl;
    IpPrefix prefix_to_advertise = {"10.1.0.0", 16};
    r1.originate_route(prefix_to_advertise);

    // More ticks to allow propagation
    for (int i = 0; i < 2; ++i) {
        std::cout << "\n--- Tick " << i + 3 << " ---" << std::endl;
        r1.tick();
        r2.tick();
        r3.tick();
    }

    // Print final routing tables
    r1.print_routing_table();
    r2.print_routing_table();
    r3.print_routing_table();
    
    // Test IP packet forwarding 
    IpPacket test_packet;
    test_packet.source_ip = "5.5.5.5";
    test_packet.destination_ip = "10.1.25.77"; // This IP is inside the 10.1.0.0/16 network
    test_packet.payload = "Hello, World!";

    r3.forward_packet(test_packet);

    return 0;
}

// Define the static member variable
std::map<std::string, Router*> Router::network;