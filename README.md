# BGP Simulator with Trust-Based Security

This project is a C++ based BGP-4 simulator that models the full path-vector logic of the Border Gateway Protocol. It includes a dynamic, voting-based trust and reputation system designed to study securing routing decisions against malicious activities like prefix hijacking. The simulation is controlled via an interactive command-line interface (CLI).

## Features

* **Core BGP-4 Protocol:** Simulates router states and the exchange of OPEN, UPDATE, KEEPALIVE, and NOTIFICATION messages.
* **Customizable Topology:** Define routers, Autonomous Systems, and the links between them in a simple `.conf` file.
* **Dynamic Routing Policies:** Influence route selection by applying `deny` policies to routers on the fly.
* **Voting-Based Trust System:** Routers build trust scores for their peers based on direct interaction and recommendations from other routers. This trust score is integrated into the BGP best-path selection algorithm.
* **Interactive Network Control:** Shut down/start up routers and drop/restore links to simulate real-world error conditions and test network resiliency.
* **Attack Simulation:** Launch BGP prefix hijacks from any router to test the effectiveness of the trust-based defense mechanism.
* **Real-time Monitoring:** Display BGP routing tables, peer status, and trust metrics for all routers.
* **Route Reflection Support:** Configure and manage route reflector clients for scalable network designs.
* **Policy-Based Filtering:** Apply inbound and outbound policies to control route propagation.
* **Dynamic Route Announcements:** Simulate normal and malicious route announcements and withdrawals.
* **Trust Score Visualization:** Monitor how trust scores evolve as routers interact and communicate recommendations.
* **Network Convergence Tracking:** Observe how the network converges after topology changes or security events.
* **Interactive CLI Interface:** User-friendly command-line interface with help documentation and command history.


## Getting Started

### Prerequisites
You will need a C++ compiler that supports the C++17 standard, such as g++.

## Installation Instructions

If you do not have `g++` installed, follow the steps below for your operating system.

### Linux

#### Ubuntu/Debian
Run the following commands to install the build-essential package:
```bash
sudo apt update
sudo apt install build-essential
```

Verify the installation:
```bash
g++ --version
```

### macOS

Install Xcode Command Line Tools, which includes `g++` (actually clang with g++ compatibility):
```bash
xcode-select --install
```

Alternatively, install via Homebrew:
```bash
brew install gcc
```

Note: The default `g++` on macOS is actually clang. If you need genuine GCC, use the Homebrew installation and invoke it as `g++-13`

### Windows

#### Option 1: MinGW-w64 (Recommended)
1. Download the MinGW-w64 installer from [mingw-w64.org](https://www.mingw-w64.org/)
2. Run the installer and select your architecture (x86_64 for 64-bit)
3. Add the `bin` directory to your system PATH (e.g., `C:\mingw-w64\bin`)
4. Verify installation in Command Prompt:
```cmd
   g++ --version
```

#### Option 2: MSYS2
1. Download and install MSYS2 from [msys2.org](https://www.msys2.org/)
2. Open MSYS2 terminal and run:
```bash
   pacman -S mingw-w64-x86_64-gcc
```
3. Add `C:\msys64\mingw64\bin` to your system PATH


### Compilation
To compile the simulator, navigate to the project directory in your terminal and run the following command:
```sh
g++ -std=c++17 -Wall -o bgp_sim simulator.cpp
```


### Running the Simulator
To run the simulator, you must provide a topology configuration file using the `-c` flag.
**Linux/macOS**
```sh
./bgp_sim -c topology.conf
```

**Windows**
```cmd
./bgp_sim.exe -c topology.conf
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
