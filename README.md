# TCP/IP Network Stack Simulator

This project is an interactive, educational simulator for the TCP/IP network stack, visualizing how data moves from the application layer down to the physical layer and back up on the receiver side. It is designed for students, educators, and anyone interested in understanding how network protocols work under the hood.

## Features
- **Step-by-step simulation** of data transmission from sender to receiver, including all major layers: Application (HTTP), Transport (TCP), Network (IP), Data Link (Ethernet), and Physical.
- **Visual breakdown** of headers and data at each layer, with color-coded displays for hex, binary, and ASCII representations.
- **Interactive controls** to initialize connections, send data, simulate packet loss, and network congestion.
- **Event log/sequence diagram** to track protocol events and state changes.
- **Congestion window and protocol statistics** for TCP behavior and network efficiency.
- **Manchester encoding** visualization at the physical layer.

## Project Structure
```
/ (root)
│
├── index.html         # Main HTML file (structure only, links to external CSS/JS)
├── css/
│   └── style.css      # All styles for the simulator
├── js/
│   └── main.js        # All JavaScript logic for simulation and UI
└── README.md          # This file
```

## How to Run
1. **Clone or download** this repository to your local machine.
2. Open `index.html` in your web browser (no server required, works as a static site).
3. Use the controls at the top to initialize a TCP connection, send data, and experiment with packet loss or congestion.

## Customization & Extending
- All styles are in `css/style.css`. You can modify colors, layout, or fonts as desired.
- All simulation logic is in `js/main.js`. For further modularity, you can split this file by functionality (e.g., `network.js`, `ui.js`, etc.).
- The simulator is designed for clarity and learning, not for production networking.

## Requirements
- Any modern web browser (Chrome, Firefox, Edge, Safari, etc.)
- No external dependencies or build tools required.

## License
This project is open source and free to use for educational and non-commercial purposes. 