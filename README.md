# Inter-AS BGP Network Simulator

A C++-based simulator for visualizing BGP routing and exploring Layer 3 vulnerabilities in a 10-router inter-AS topology.

# Features

* Models the full path-vector logic for BGP-4 over IPv4.

* Routers establish simulated TCP connections and exchange BGP messages (OPEN, UPDATE, NOTIFICATION, KEEPALIVE).

* "Cold start" functionality: routers discover neighbors and build routing tables from scratch.

* Simulates error conditions, such as routers going offline and links being dropped.
  * Simple Policy Control: Enables the configuration of basic routing policies, such as AS-path prepending, to manually influence path selection.
  * Route Hijack Simulation: Allows a user to designate a malicious router to broadcast false route announcements, demonstrating how traffic can be redirected.
  * Trust Score: A simple, static trust score for each router. This score can be used as a primary factor or a tie-breaker in the BGP path selection process to simulate a basic defense mechanism.

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
