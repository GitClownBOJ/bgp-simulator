# Inter-AS BGP Network Simulator

A C++-based simulator for visualizing BGP routing and exploring Layer 3 vulnerabilities in a 10-router inter-AS topology.

# Features

* Core BGP-4
 * Models the full path-vector logic for BGP-4 over IPv4
 * Routers establish simulated TCP connections and exchange BGP messages (OPEN, UPDATE, NOTIFICATION, KEEPALIVE)
 * "Cold start" functionality: routers discover neighbors and build routing tables from scratch
 * Simulates error conditions, such as routers going offline and links being dropped

* Customizable network environment
 * Network topology is fully customizable via a configuration file, specifying routers and their links
 * Administrators can enforce local policies on each router to influence path selection

* Low-level packet processing
 * Simulates IP packet forwarding based on the constructed routing tables
 * Routers process incoming packets as a stream of bits, parsing IPv4 header fields to make forwarding decisions
 * Includes a set of manually created IP packets for simulation scenarios

* Trust and reputation system
 * Implements a dynamic, voting-based trust model to secure routing decisions
 * Trust information is exchanged between routers, either via a new BGP message type
 * Neighbors of neighbors vote on a router's reliability
 * A "total trust" score is calculated
 * The final trust value is integrated into the BGP best-path selection algorithm

* Attack simulation
 * Designate a malicious router to broadcast false route announcements to test the effectiveness of the trust system

# Getting Started
Prerequisites

* A C++ compiler with C++17 support (e.g., GCC 7+, Clang 5+)

* CMake 3.10+

* Make

Installation

1. Clone the repository:

```sh
git clone git@github.com:GitClownBOJ/bgp-simulator.git
cd bgp-simulator
```
2. Configure the build environment

```sh
mkdir build && cd build
cmake ..
```

3. Compile the project

```sh
make
```
