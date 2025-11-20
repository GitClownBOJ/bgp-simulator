# BGP Simulator with Trust-Based Security

This project is a C++ based BGP-4 simulator that models the full path-vector logic of the Border Gateway Protocol. It includes a dynamic, voting-based trust and reputation system designed to secure routing decisions against malicious activities like prefix hijacking. The simulation is controlled via an interactive command-line interface (CLI).

## Features

* **Core BGP-4 Protocol:** Simulates router states and the exchange of OPEN, UPDATE, KEEPALIVE, and NOTIFICATION messages.
* **Customizable Topology:** Define routers, Autonomous Systems, and the links between them in a simple `.conf` file.
* **Dynamic Routing Policies:** Influence route selection by applying `deny` policies to routers on the fly.
* **Voting-Based Trust System:** Routers build trust scores for their peers based on direct interaction and recommendations from other routers. This trust score is integrated into the BGP best-path selection algorithm.
* **Interactive Network Control:** Shut down/start up routers and drop/restore links to simulate real-world error conditions and test network resiliency.
* **Attack Simulation:** Launch BGP prefix hijacks from any router to test the effectiveness of the trust-based defense mechanism.
* **Packet Forwarding:** A `ping` command to simulate the data plane, showing how an IP packet would be forwarded based on the current routing tables.

## Getting Started

### Prerequisites
You will need a C++ compiler that supports the C++17 standard, such as g++.

### Compilation
To compile the simulator, navigate to the project directory in your terminal and run the following command:
```sh
g++ -std=c++17 -Wall -o bgp_sim simulator.cpp
```

## Usage

### Running the Simulator
To run the simulator, you must provide a topology configuration file using the `-c` flag.
```sh
./bgp_sim -c topology.conf
```
The simulator will load the network, allow it to converge, and then present you with an interactive `BGP-Sim>` prompt.

### Command Reference
The following commands are available in the simulator's CLI:

| Command | Description |
| :--- | :--- |
| `show ip bgp <router_id>` | Display the BGP routing table for a specific router. |
| `show peers <router_id>` | Display the status of all BGP peers for a router. |
| `show trust <router_id>` | Display the calculated trust scores a router holds for its peers. |
| `tick [n]` | Advance the simulation by `n` ticks (default is 1). |
  `neighbor <r_id> <p_ip> remote-as <asn>` | Configure a new peer. |
  `neighbor <r_id> <p_ip> route-reflector-client` | Configure peer as route reflector client. |
| `announce <r_id> <p/l>` | Make a router announce a (potentially false) route for a prefix. |
| `withdraw <r_id> <p/l>` | Make a router withdraw its announcement for a prefix. |
| `policy <r_id> [in\|out] deny <p/l>`| Apply an outbound or inbound policy to deny a prefix. |
| `shutdown <router_id>` | Shut down a router and all its BGP sessions. |
| `startup <router_id>` | Start up a previously shut down router. |
  `resend-routes <router_id>` | Resend all routes from a router to its peers. |
| `help` | Display this list of commands. |
| `exit` / `quit` | Exit the simulator. |