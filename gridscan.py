#!/usr/bin/python3
#
# Written in Python 3.6.9
# 
# Maybe perimeterscan.py or periscan.py rather than gridscan.py?
# 
# MADE BY Insomniac\x00
# NOTE: Add capability to check and warn user if there's insufficient creds to create dir!
# NOTE: Add capability to upload LinEnum.sh and run it on remote server thru SSH, then 
# send output back and save on local file. Maybe something like this also for windows machines?
# NOTE: Add gobuster search if port 80/8080/443 are found & maybe nikto and/or sparta scans aswell?
# Gobuster should use dirs based on user input, with small being common.txt, med being small-directories.txt
# and large being medium-directories.txt. 
# Also allow user to select wordlist manually; prompt user if required wordlists arent found.

import sys, os
from inputimeout import inputimeout, TimeoutOccurred


# Define colors for better readability when printing output
class bcolors: 
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



# Taking arguments into account
if __name__ == '__main__':

    try:
        target = sys.argv[1]
        scan_type = sys.argv[2]
        scan_type = scan_type.lower()
        print(f"{bcolors.WARNING}NOTE: Requires nmap to work!{bcolors.ENDC}\n")
        print(f"{bcolors.PURPLE}---------------------------------------------------------" + bcolors.ENDC)
        print(f"{bcolors.PURPLE}-----------------------made by---------------------------" + bcolors.ENDC)
        print(f"{bcolors.PURPLE}--------------------{bcolors.BLUE}v0id.cat{bcolors.ENDC}{bcolors.PURPLE}------------------------" + bcolors.ENDC)
        print(f"{bcolors.PURPLE}---------------------------------------------------------\n" + bcolors.ENDC)

    except IndexError:
        print('Usage: %s <target ip> <scan type>' % sys.argv[0])
        print('Example: gridscan.py 192.168.1.1 Full')
        print("\n\nScan types available are: \n")
        print("Quick OR Q               - Quick scan for any open ports.")
        print("UDP OR U                 - Runs a UDP scan on the target.")
        print("Regular OR Reg OR R      - Runs regular scripts and fingerprints for service versions.")
        print("Full OR F                - Does a more thorough & aggressive TCP scan on target.")
        sys.exit(-1)



quickscan_results_available = False
udpscan_results_available = False
regularscan_results_available = False
fullscan_results_available = False

# Check if nmap dir exists, otherwise create it.

def filecheck():
    global quickscan_results_available, udpscan_results_available, regularscan_results_available, fullscan_results_available # Import global vars
    if os.path.isdir('./nmap'): 
        if os.path.isfile('./nmap/quickscan.nmap'):
            quickscan_results_available = True
        else:
            quickscan_results_available = False

        if os.path.isfile('./nmap/udpscan.nmap'):
            udpscan_results_available = True
        else:
            udpscan_results_available = False

        if os.path.isfile('./nmap/regularscan.nmap'):
            regularscan_results_available = True
        else:
            regularscan_results_available = False

        if os.path.isfile('./nmap/fullscan.nmap'):
            fullscan_results_available = True
        else:
            fullscan_results_available = False

    elif not os.path.isdir('./nmap'):
        print(f"{bcolors.WARNING}[*] nmap directory not found. Creating... {bcolors.ENDC}")
        os.system('mkdir nmap')
        print(f"{bcolors.WARNING}[*] Created!{bcolors.ENDC}")
        #filecheck()
    else:
        print("Unknown error occurred in function \"filecheck()\".")
        pass


# Defining scan types

def quickscan(): # Quickly scan all ports and see which are open
    cmd = "nmap -Pn -T4 --max-retries 1 --max-scan-delay 20 --open -oA nmap/quickscan %s" % target


    while quickscan_results_available: # While loop to return to if loop incase user input is incorrect.
        try:
            print(f"{bcolors.WARNING}[*] Previous scan files have been found in nmap dir!{bcolors.ENDC}\n")
            # rerun_scan = input(f"{bcolors.BOLD}[*] Would you like to rerun the scan? y/N {bcolors.ENDC}")
            rerun_scan = inputimeout(prompt=f"{bcolors.BOLD}[*] Would you like to rerun the scan? y/N {bcolors.ENDC}", timeout = 30) # Setting input timeout
            
            rerun_scan = rerun_scan.lower()

            if rerun_scan == "y":
                print(f"\n{bcolors.BOLD}[*] Running scan type: Quick{bcolors.ENDC}")
                os.system(cmd)
                break

            elif rerun_scan == "n":
                print(f"{bcolors.WARNING}[*] Scan rerun denied by user. Printing old results instead.{bcolors.ENDC}")
                catfile = "cat nmap/quickscan.nmap"
                os.system(catfile)
                break

            else:
                print(f"{bcolors.FAIL}[-] Error! Please use either Y or N to signify your response!{bcolors.ENDC}")


        except TimeoutOccurred: # If timed out, do the following...
            print(f"{bcolors.WARNING}[*] TIMED OUT: Printing old results, then rerunning scans just in case...{bcolors.ENDC}")
            catfile = 'cat nmap/quickscan.nmap'
            print(f'{bcolors.BOLD}----------------------------{bcolors.WARNING}OLD RESULTS{bcolors.ENDC}{bcolors.BOLD}----------------------------{bcolors.ENDC}')
            os.system(catfile)
            print(f'{bcolors.BOLD}---------------------------{bcolors.WARNING}END OF RESULTS{bcolors.ENDC}{bcolors.BOLD}--------------------------{bcolors.ENDC}')
            print(f"\n{bcolors.BOLD}[*] Running scan type: Quick{bcolors.ENDC}")
            os.system(cmd)
            break


    while not quickscan_results_available: # If no results are found, run the scan
        print(f"\n{bcolors.BOLD}[*] Running scan type: Quick{bcolors.ENDC}")
        os.system(cmd)
        break




def udpscan(): # Scan UDP ports
    cmd = "nmap -Pn -sU --max-retries 1 --open -oA nmap/udpscan %s" % target

    while udpscan_results_available:
        try:
            print(f"{bcolors.WARNING}[*] Previous scan files have been found in nmap dir!{bcolors.ENDC}\n")
            rerun_scan = inputimeout(prompt=f"{bcolors.BOLD}[*] Would you like to rerun the scan? y/N {bcolors.ENDC}", timeout = 30)
            rerun_scan = rerun_scan.lower()

            if rerun_scan == "y":
                print(f"\n{bcolors.BOLD}[*] Running scan type: UDP{bcolors.ENDC}")
                os.system(cmd)
                break

            elif rerun_scan == "n":
                print(f"{bcolors.WARNING}[*] Scan rerun denied by user. Printing old results instead.{bcolors.ENDC}")
                catfile = "cat nmap/udpscan.nmap"
                os.system(catfile)
                break

            else:
                print(f"{bcolors.FAIL}[-] Error! Please use either Y or N to signify your response!{bcolors.ENDC}")


        except TimeoutOccurred:
            print(f"{bcolors.WARNING}[*] TIMED OUT: Printing old results, then rerunning scans just in case...{bcolors.ENDC}")
            catfile = 'cat nmap/udpscan.nmap'
            print(f'{bcolors.BOLD}----------------------------{bcolors.WARNING}OLD RESULTS{bcolors.ENDC}{bcolors.BOLD}----------------------------{bcolors.ENDC}')
            os.system(catfile)
            print(f'{bcolors.BOLD}---------------------------{bcolors.WARNING}END OF RESULTS{bcolors.ENDC}{bcolors.BOLD}--------------------------{bcolors.ENDC}')
            print(f"\n{bcolors.BOLD}[*] Running scan type: UDP{bcolors.ENDC}")
            os.system(cmd)
            break


    while not udpscan_results_available:
        print(f"\n{bcolors.BOLD}[*] Running UDP scan...{bcolors.ENDC}")
        os.system(cmd)
        break




def regscan(): # Scan with all regular scripts and fingerprint for service versions

    cmd = "nmap -Pn -sC -sV -oA nmap/regularscan %s" % target


    while regularscan_results_available:
        try:
            print(f"{bcolors.WARNING}[*] Previous scan files have been found in nmap dir!{bcolors.ENDC}\n")
            rerun_scan = inputimeout(prompt=f"{bcolors.BOLD}[*] Would you like to rerun the scan? y/N {bcolors.ENDC}", timeout = 30)
            rerun_scan = rerun_scan.lower()

            if rerun_scan == "y":
                print(f"\n{bcolors.BOLD}[*] Running scan type: Regular{bcolors.ENDC}")
                os.system(cmd)
                break

            elif rerun_scan == "n":
                print(f"{bcolors.WARNING}[*] Scan rerun denied by user. Printing old results instead.{bcolors.ENDC}")
                catfile = "cat nmap/regularscan.nmap"
                os.system(catfile)
                break

            else:
                print(f"{bcolors.FAIL}[-] Error! Please use either Y or N to signify your response!{bcolors.ENDC}")


        except TimeoutOccurred:
            print(f"{bcolors.WARNING}[*] TIMED OUT: Printing old results, then rerunning scans just in case...{bcolors.ENDC}")
            catfile = 'cat nmap/regularscan.nmap'
            print(f'{bcolors.BOLD}----------------------------{bcolors.WARNING}OLD RESULTS{bcolors.ENDC}{bcolors.BOLD}----------------------------{bcolors.ENDC}')
            os.system(catfile)
            print(f'{bcolors.BOLD}---------------------------{bcolors.WARNING}END OF RESULTS{bcolors.ENDC}{bcolors.BOLD}--------------------------{bcolors.ENDC}')
            print(f"\n{bcolors.BOLD}[*] Running scan type: Regular{bcolors.ENDC}")
            os.system(cmd)
            break


    while not regularscan_results_available:
        print(f"\n{bcolors.BOLD}[*] Running scan type: Regular{bcolors.ENDC}")
        os.system(cmd) # Running nmap
        break



# NOTE: Add CVE / vulnerability scanning thru nmap NSE 
# NOTE: Instead of running full scan on all ports, run quick scan first, then thorough scan on open ports.

def fullscan():
    cmd = "nmap -A -Pn -p- -sV --max-retries 1 --max-rate 500 --max-scan-delay 20 -T3 -v -oA nmap/fullscan %s" % target # john cena asks ARE YOU SURE ABOUT THAT?

    while fullscan_results_available:
        try:
            print(f"{bcolors.WARNING}[*] Previous scan files have been found in nmap dir!{bcolors.ENDC}\n")
            rerun_scan = inputimeout(prompt=f"{bcolors.BOLD}[*] Would you like to rerun the scan? y/N {bcolors.ENDC}", timeout = 30)
            rerun_scan = rerun_scan.lower()

            if rerun_scan == "y":
                print(f"\n{bcolors.BOLD}[*] Running scan type: Full{bcolors.ENDC}")
                os.system(cmd)
                break

            elif rerun_scan == "n":
                print(f"{bcolors.WARNING}[*] Scan rerun denied by user. Printing old results instead.{bcolors.ENDC}")
                catfile = "cat nmap/fullscan.nmap"
                os.system(catfile)
                break

            else:
                print(f"{bcolors.FAIL}[-] Error! Please use either Y or N to signify your response!{bcolors.ENDC}")


        except TimeoutOccurred:
            print(f"{bcolors.WARNING}[*] TIMED OUT: Printing old results, then rerunning scans just in case...{bcolors.ENDC}")
            catfile = 'cat nmap/fullscan.nmap'
            print(f'{bcolors.BOLD}----------------------------{bcolors.WARNING}OLD RESULTS{bcolors.ENDC}{bcolors.BOLD}----------------------------{bcolors.ENDC}')
            os.system(catfile)
            print(f'{bcolors.BOLD}---------------------------{bcolors.WARNING}END OF RESULTS{bcolors.ENDC}{bcolors.BOLD}--------------------------{bcolors.ENDC}')
            print(f"\n{bcolors.BOLD}[*] Running scan type: Full{bcolors.ENDC}")
            os.system(cmd)
            break

    while not fullscan_results_available:
        print(f"\n{bcolors.BOLD}[*] Running scan type: Full{bcolors.ENDC}")
        os.system(cmd)


filecheck()

# Running requested scan type
if scan_type == "reg" or scan_type == 'regularscan' or scan_type == 'r':
    regscan()
elif scan_type == "quick" or scan_type == 'q':
    quickscan()
elif scan_type == "full" or scan_type == 'f':
    fullscan()
elif scan_type == "udp" or scan_type == 'u':
    udpscan()