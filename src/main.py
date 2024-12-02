# src/main.py

import argparse
from detector import start_sniffer
from config import DEFAULT_INTERFACE, LOG_FILE_PATH

def parse_arguments():
    """
    Parse command-line arguments for the network scan detection tool.
    
    :return: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Lightweight Network Scan Detector"
    )
    parser.add_argument(
        "-i", "--interface", 
        type=str, 
        default=DEFAULT_INTERFACE,
        help=f"Network interface to monitor (default: {DEFAULT_INTERFACE})"
    )
    parser.add_argument(
        "-l", "--log", 
        type=str, 
        default=LOG_FILE_PATH,
        help=f"Path to the log file (default: {LOG_FILE_PATH})"
    )
    return parser.parse_args()

def main():
    """
    Entry point for the Network Scan Detector CLI.
    """
    args = parse_arguments()
    
    # Set log file path in the config module
    global LOG_FILE_PATH
    LOG_FILE_PATH = args.log
    
    print("[*] Network Scan Detector")
    print(f"[*] Monitoring interface: {args.interface}")
    print(f"[*] Logging to: {args.log}")
    
    # Start the sniffer
    start_sniffer(interface=args.interface)

if __name__ == "__main__":
    main()
