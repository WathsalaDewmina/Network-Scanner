# Network Scanner

## Benefits of Network Scanner

A network scanner is a valuable tool in the realm of network security and administration. It allows you to discover devices connected to your network, identify open ports, detect potential vulnerabilities, and monitor network activity. Network scanners are essential for network administrators, penetration testers, and security professionals to maintain network integrity and security.

<img src="netScanner.png" alt="MAC Address Changer Screenshot" width="600"/>


## Installation

1. **Download the Source Code:**
    - Clone the repository to your local machine using the following command:
        ```sh
        git clone https://github.com/WathsalaDewmina/Network-Scanner.git
        ```

2. **Install Dependencies:**
    - Ensure you have [pip](https://pypi.org/project/pip/) installed on your machine.
    - Also make you you have python2 or python3 installed in your device - [python](https://www.python.org/downloads/)

      
3. **Install Modules:**
    - Install the required Python packages using `requirements.txt`:
        ```sh
        pip3 install -r requirements.txt
        ```

## Running the Script

1. **Help Screen:**
    - To view the help screen of the script, execute the following command in your terminal:
        ```sh
        python3 networkScanner.py -h
        ```

2. **Run the Script:**
    - Execute the following command in your terminal to run the network scanner:
        ```sh
        python3 networkScanner.py -r <ip_addr>
        ```

    - Replace `<ip_addr>` with the IP address or IP range you want to scan.

### Examples

Scan all IP addresses in the range 192.168.8.0 to 192.168.8.255:

```sh
python3 networkScanner.py -r 192.168.8.0/24
