#!/usr/bin/python3
# Written in Python 3
# 
# MADE BY v0idcat

import sys, os, select, time

# Define colors for better readability when printing output
class bcolors: 
    PURPLE = '\033[95m'     # Purple text
    BLUE = '\033[94m'       # Blue text
    GREEN = '\033[92m'      # Green text
    WARNING = '\033[93m'    # Yellow text
    FAIL = '\033[91m'       # Red text
    ENDC = '\033[0m'        # Return to default text format
    BOLD = '\033[1m'        # Bold Text
    UNDERLINE = '\033[4m'   # Underlines text
    TIMEOUT = '\033[43m'    # Yellow background
    BLK = '\033[30m'        # Black text



# Taking arguments into account
if __name__ == '__main__':

    try:
        target = sys.argv[1]
        scan_type = sys.argv[2]
        scan_type = scan_type.lower()
        print(f"{bcolors.WARNING}NOTE: Requires nmap & gobuster{bcolors.ENDC}\n")
        print(f"{bcolors.PURPLE}---------------------------------------------------------" + bcolors.ENDC)
        print(f"{bcolors.PURPLE}-----------------------made by---------------------------" + bcolors.ENDC)
        print(f"{bcolors.PURPLE}-----------------------{bcolors.BLUE}v0id.cat{bcolors.ENDC}{bcolors.PURPLE}--------------------------" + bcolors.ENDC)
        print(f"{bcolors.PURPLE}---------------------------------------------------------\n" + bcolors.ENDC)

    except IndexError:
        print('Usage: %s <target ip> <scan type>' % sys.argv[0])
        print('Example: gridscan.py 192.168.1.1 Full')
        print("\n\nScan types available are: \n")
        print("Quick OR Q               - Quick scan for any open ports.")
        print("UDP OR U                 - Runs a UDP scan on the target.")
        print("Regular OR Reg OR R      - Runs regular scripts and fingerprints for service versions.")
        print("Vulnscan OR Vuln OR V    - Runs vulnerability scan using quick scan results.")
        print("Full OR F                - Does a more thorough & aggressive TCP scan on target.")
        print("Gobuster OR G            - Runs gobuster on ports 80/8080/443 depending on what is found with a quickscan.")
        sys.exit(-1)


# Timed input function & class
class TimeoutOccurred(Exception): # Continue execution after timer has expired
    pass

def tinput(prompt, timeout):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    ready, _, _ = select.select([sys.stdin], [],[], timeout) # ready var contains stdin, two underscores are wlist and xlist args from select() func
    if ready:
        return sys.stdin.readline().rstrip('\n') # Expect stdin to be line-buffered
    raise TimeoutOccurred


# Declaring global variables
quickscan_results_available = False
udpscan_results_available = False
regularscan_results_available = False
fullscan_results_available = False
vulnscan_results_available = False
quickscancmd = "nmap -Pn -p- -oA nmap/quickscan %s" % target
udpscancmd = "nmap -Pn -sU -sC -sV --script=vuln -oA nmap/udpscan %s" % target
regscancmd = "nmap -Pn -sC -sV -oA nmap/regularscan %s" % target

def filecheck(): # Check if nmap dir exists, otherwise create it.
    global quickscan_results_available, udpscan_results_available, regularscan_results_available, fullscan_results_available, vulnscan_results_available # Import global vars
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

        if os.path.isfile('./nmap/vulnscan.nmap'):
            vulnscan_results_available = True
        else:
            vulnscan_results_available = False

        if os.path.isfile('./nmap/fullscan.nmap'):
            fullscan_results_available = True
        else:
            fullscan_results_available = False

    elif not os.path.isdir('./nmap'):
        print(f"{bcolors.WARNING}[*] nmap directory not found. Creating... {bcolors.ENDC}")
        #privcheck() # Run to check if we have the proper privileges to create the directory. Otherwise, what's the point if we can't save info?
        os.system('mkdir nmap')
        print(f"{bcolors.WARNING}[*] Created!{bcolors.ENDC}")
        
    else:
        print("Unknown error occurred in function \"filecheck()\".")
        pass


# Defining scan types
def quickscan(): # Quickly scan all ports and see which are open
    global quickscancmd
    # cmd = "nmap -Pn -p- -T4 --max-retries 1 --max-scan-delay 20 --open -oA nmap/quickscan %s" % target

    while quickscan_results_available: # While loop to return to if loop incase user input is incorrect.
        try:
            print(f"{bcolors.WARNING}[*] Previous scan files have been found in nmap dir!{bcolors.ENDC}\n")
            rerun_scan = tinput(f"{bcolors.BOLD}[*] Would you like to rerun the quick scan? y/N {bcolors.ENDC}", 30) # Setting input timeout
            
            rerun_scan = rerun_scan.lower()

            if rerun_scan == "y":
                print(f"\n{bcolors.BOLD}[*] Running scan type: Quick{bcolors.ENDC}")
                os.system(quickscancmd)
                break

            elif rerun_scan == "n":
                print(f"{bcolors.WARNING}[*] Scan rerun denied by user. Printing old results instead.{bcolors.ENDC}")
                catfile = "cat nmap/quickscan.nmap"
                os.system(catfile)
                break

            else:
                print(f"{bcolors.FAIL}[-] Error! Please use either Y or N to signify your response!{bcolors.ENDC}")


        except TimeoutOccurred: # If timed out, do the following...
            print(f"\n{bcolors.TIMEOUT}{bcolors.BLK}[*] TIMED OUT: Printing old results, then rerunning scans just in case...{bcolors.ENDC}")
            catfile = 'cat nmap/quickscan.nmap'
            print(f'{bcolors.BOLD}----------------------------{bcolors.WARNING}OLD RESULTS{bcolors.ENDC}{bcolors.BOLD}----------------------------{bcolors.ENDC}')
            os.system(catfile)
            print(f'{bcolors.BOLD}---------------------------{bcolors.WARNING}END OF RESULTS{bcolors.ENDC}{bcolors.BOLD}--------------------------{bcolors.ENDC}')
            print(f"\n{bcolors.BOLD}[*] Running scan type: Quick{bcolors.ENDC}")
            os.system(quickscancmd)
            break


    while not quickscan_results_available: # If no results are found, run the scan
        print(f"\n{bcolors.BOLD}[*] Running scan type: Quick{bcolors.ENDC}")
        os.system(quickscancmd)
        break



def udpscan(): # Scan UDP ports
    global udpscancmd
    # cmd = "nmap -Pn -sU -sC -sV --script vulners --script-args mincvss=7.0 --max-retries 1 --open -oA nmap/udpscan %s" % target

    while udpscan_results_available:
        try:
            print(f"{bcolors.WARNING}[*] Previous scan files have been found in nmap dir!{bcolors.ENDC}\n")
            rerun_scan = tinput(f"{bcolors.BOLD}[*] Would you like to rerun the UDP scan? y/N {bcolors.ENDC}", 30)
            rerun_scan = rerun_scan.lower()

            if rerun_scan == "y":
                print(f"\n{bcolors.BOLD}[*] Running scan type: UDP{bcolors.ENDC}")
                os.system(udpscancmd)
                break

            elif rerun_scan == "n":
                print(f"{bcolors.WARNING}[*] Scan rerun denied by user. Printing old results instead.{bcolors.ENDC}")
                catfile = "cat nmap/udpscan.nmap"
                os.system(catfile)
                break

            else:
                print(f"{bcolors.FAIL}[-] Error! Please use either Y or N to signify your response!{bcolors.ENDC}")


        except TimeoutOccurred:
            print(f"\n{bcolors.TIMEOUT}{bcolors.BLK}[*] TIMED OUT: Printing old results, then rerunning scans just in case...{bcolors.ENDC}")
            catfile = 'cat nmap/udpscan.nmap'
            print(f'{bcolors.BOLD}----------------------------{bcolors.WARNING}OLD RESULTS{bcolors.ENDC}{bcolors.BOLD}----------------------------{bcolors.ENDC}')
            os.system(catfile)
            print(f'{bcolors.BOLD}---------------------------{bcolors.WARNING}END OF RESULTS{bcolors.ENDC}{bcolors.BOLD}--------------------------{bcolors.ENDC}')
            print(f"\n{bcolors.BOLD}[*] Running scan type: UDP{bcolors.ENDC}")
            os.system(udpscancmd)
            break


    while not udpscan_results_available:
        print(f"\n{bcolors.BOLD}[*] Running UDP scan...{bcolors.ENDC}")
        os.system(udpscancmd)
        break



def vulnscan():
    global vulnscan_results_available
    catfullfile = "cat nmap/vulnscan.nmap"
    parsequickfile = "cat nmap/quickscan.nmap | grep 'open\\|filtered' | cut -d \" \" -f 1 | cut -d \"/\" -f 1 | tr \"\\n\" \",\" | head -c-1 > nmap/parsedquickscan.txt" # Command to parse quickscan file. 

    if os.path.isfile("nmap/quickscan.nmap"):
        print(f"{bcolors.WARNING}[*] Old quickscan results have been found! Parsing data for vuln scan...")
        os.system(parsequickfile)
        f = open("nmap/parsedquickscan.txt", "r")
        if f.mode == "r":
            quickscanopenports = f.read()
        f.close()
        cmd = "nmap --script vuln -Pn -p %s -oA nmap/vulnscan %s" %(quickscanopenports, target)

    elif not os.path.isfile("nmap/quickscan.nmap"):
        print(f"{bcolors.WARNING}\n[*] No old quick scan results found, running now to parse...{bcolors.ENDC}")
        os.system(quickscancmd)
        os.system(parsequickfile)
        print(f"{bcolors.GREEN}\n[+] Scan completed & parsed, starting vuln scan now...{bcolors.ENDC}")
        f = open("nmap/parsedquickscan.txt", "r")
        if f.mode == "r":
            quickscanopenports = f.read()
        f.close()
        # This command is repeated twice in this function. Is this necessary?
        cmd = "nmap --script vuln -Pn -p %s -oA nmap/vulnscan %s" %(quickscanopenports, target)

    else:
        print(f"{bcolors.FAIL}Error occured while checking if quickscan results were available.")
        pass


    while vulnscan_results_available:
        try:
            print(f"{bcolors.WARNING}[*] Previous scan files have been found in nmap dir!{bcolors.ENDC}\n")
            rerun_scan = tinput(f"{bcolors.BOLD}[*] Would you like to rerun the vuln scan? y/N {bcolors.ENDC}", 30)
            rerun_scan = rerun_scan.lower()
            if rerun_scan == "y":
                print(f"\n{bcolors.BOLD}[*] Running scan type: Vuln{bcolors.ENDC}")
                os.system(cmd) 
                break

            elif rerun_scan == "n":
                print(f"{bcolors.WARNING}[*] Scan rerun denied by user. Printing old results instead.{bcolors.ENDC}")
                os.system(catfullfile)
                break

            else:
                print(f"{bcolors.FAIL}[-] Error! Please use either Y or N to signify your response!{bcolors.ENDC}")

        except TimeoutOccurred:
            print(f"\n{bcolors.TIMEOUT}{bcolors.BLK}[*] TIMED OUT: Printing old results, then rerunning scans just in case...{bcolors.ENDC}")
            print(f'{bcolors.BOLD}----------------------------{bcolors.WARNING}OLD RESULTS{bcolors.ENDC}{bcolors.BOLD}----------------------------{bcolors.ENDC}')
            os.system(catfullfile)
            print(f'{bcolors.BOLD}---------------------------{bcolors.WARNING}END OF RESULTS{bcolors.ENDC}{bcolors.BOLD}--------------------------{bcolors.ENDC}')
            print(f"\n{bcolors.BOLD}[*] Running scan type: Vuln{bcolors.ENDC}")
            os.system(cmd) 
            break


    while not vulnscan_results_available:
        print(f"\n{bcolors.BOLD}[*] Running scan type: Vuln{bcolors.ENDC}")
        os.system(cmd) # Add command to run vuln scan here
        break



def regscan(): # Scan with all regular scripts and fingerprint for service versions
    global regscancmd

    while regularscan_results_available:
        try:
            print(f"{bcolors.WARNING}[*] Previous scan files have been found in nmap dir!{bcolors.ENDC}\n")
            rerun_scan = tinput(f"{bcolors.BOLD}[*] Would you like to rerun the regular scan? y/N {bcolors.ENDC}", 30)
            rerun_scan = rerun_scan.lower()

            if rerun_scan == "y":
                print(f"\n{bcolors.BOLD}[*] Running scan type: Regular{bcolors.ENDC}")
                os.system(regscancmd)
                break

            elif rerun_scan == "n":
                print(f"{bcolors.WARNING}[*] Scan rerun denied by user. Printing old results instead.{bcolors.ENDC}")
                catfile = "cat nmap/regularscan.nmap"
                os.system(catfile)
                break

            else:
                print(f"{bcolors.FAIL}[-] Error! Please use either Y or N to signify your response!{bcolors.ENDC}")


        except TimeoutOccurred:
            print(f"\n{bcolors.TIMEOUT}{bcolors.BLK}[*] TIMED OUT: Printing old results, then rerunning scans just in case...{bcolors.ENDC}")
            catfile = 'cat nmap/regularscan.nmap'
            print(f'{bcolors.BOLD}----------------------------{bcolors.WARNING}OLD RESULTS{bcolors.ENDC}{bcolors.BOLD}----------------------------{bcolors.ENDC}')
            os.system(catfile)
            print(f'{bcolors.BOLD}---------------------------{bcolors.WARNING}END OF RESULTS{bcolors.ENDC}{bcolors.BOLD}--------------------------{bcolors.ENDC}')
            print(f"\n{bcolors.BOLD}[*] Running scan type: Regular{bcolors.ENDC}")
            os.system(regscancmd)
            break


    while not regularscan_results_available:
        print(f"\n{bcolors.BOLD}[*] Running scan type: Regular{bcolors.ENDC}")
        os.system(regscancmd) # Running nmap
        break



def gobusterscan():
    global quickscancmd
    parsequickfile = "cat nmap/quickscan.nmap | grep 'open\\|filtered' | cut -d \" \" -f 1 | cut -d \"/\" -f 1 | tr \"\\n\" \",\" | head -c-1 > nmap/parsedquickscan.txt" # Command to parse quickscan file.
    if os.path.isfile("nmap/quickscan.nmap"):
        print(f"{bcolors.WARNING}[*] Old quickscan results have been found! Parsing data for full scan...")
        os.system(parsequickfile)
        f = open("nmap/parsedquickscan.txt", "r")
        if f.mode == "r":
            quickscanopenports = f.read()
        f.close()
    elif not os.path.isfile("nmap/quickscan.nmap"):
        # quickscancmd = "nmap -Pn -p- -T4 --max-retries 1 --max-scan-delay 20 --open -oA nmap/quickscan %s" % target
        # quickscancmd = "nmap -Pn -p- -oA nmap/quickscan %s" % target # Imported from global var

        print(f"{bcolors.WARNING}\n[*] No old quick scan results found, running now to parse...{bcolors.ENDC}")
        os.system(quickscancmd)
        os.system(parsequickfile)
        f = open("nmap/parsedquickscan.txt", "r")
        if f.mode == "r":
            quickscanopenports = f.read()
        f.close()
        print(f"{bcolors.GREEN}\n[+] Scan completed & parsed, starting gobuster scan now...{bcolors.ENDC}")

    while not os.path.isfile("gobuster80results"): # Start while loop for port 80
        try:
            if "80" in quickscanopenports:
                gobustertextprint = f"\n{bcolors.BOLD}[*] Running gobuster...{bcolors.ENDC}"
                cmdrungobuster = "gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://%s:80 -o gobuster80results" % target
                rungobuster = tinput(f"{bcolors.BLUE}[+] Port 80 found on target! Would you like to run gobuster? y/N {bcolors.ENDC}", 30)
                rungobuster = rungobuster.lower()
                if rungobuster == "y":
                    os.system(cmdrungobuster)
                    break
                elif rungobuster == "n":
                    print(f"{bcolors.WARNING}[-] Skipping port 80...")
                    break
                else:
                    print(f"{bcolors.FAIL}[-] ERROR Handling input. Please type y or N.")
            else:
                break
        except TimeoutOccurred:
            catgobusterresults = "cat gobuster80results"
            print(f"\n{bcolors.TIMEOUT}{bcolors.BLK}[*] TIMED OUT: Printing old results, then rerunning scans just in case...{bcolors.ENDC}")
            print(f'{bcolors.BOLD}----------------------------{bcolors.WARNING}OLD RESULTS{bcolors.ENDC}{bcolors.BOLD}----------------------------{bcolors.ENDC}')
            os.system(catgobusterresults)
            print(f'{bcolors.BOLD}---------------------------{bcolors.WARNING}END OF RESULTS{bcolors.ENDC}{bcolors.BOLD}--------------------------{bcolors.ENDC}')
            print(gobustertextprint)
            os.system(cmdrungobuster)
            break


    while not os.path.isfile("gobuster8080results"): # Start while loop for port 8080
        try:
            if "8080" in quickscanopenports:
                cmdrungobuster = "gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://%s:8080 -o gobuster8080results" % target
                rungobuster = tinput(f"{bcolors.BLUE}[+] Port 8080 found on target! Would you like to run gobuster? y/N {bcolors.ENDC}", 30)
                rungobuster = rungobuster.lower()
                if rungobuster == "y":
                    os.system(cmdrungobuster)
                    break
                elif rungobuster == "n":
                    print(f"{bcolors.WARNING}[-] Skipping port 8080...")
                    break
                else:
                    print(f"{bcolors.FAIL}[-] ERROR Handling input. Please type y or N.")
            else:
                break
        except TimeoutOccurred:
            catgobusterresults = "cat gobuster8080results"
            print(f"\n{bcolors.TIMEOUT}{bcolors.BLK}[*] TIMED OUT: Printing old results, then rerunning scans just in case...{bcolors.ENDC}")
            print(f'{bcolors.BOLD}----------------------------{bcolors.WARNING}OLD RESULTS{bcolors.ENDC}{bcolors.BOLD}----------------------------{bcolors.ENDC}')
            os.system(catgobusterresults)
            print(f'{bcolors.BOLD}---------------------------{bcolors.WARNING}END OF RESULTS{bcolors.ENDC}{bcolors.BOLD}--------------------------{bcolors.ENDC}')
            print(gobustertextprint)
            os.system(cmdrungobuster)
            break


    while not os.path.isfile("gobuster443results"): # Start while loop for port 443
        try:
            if "443" in quickscanopenports:
                cmdrungobuster = "gobuster dir -w /usr/share/wordlists/dirb/common.txt -u https://%s:443 -o gobuster443results" % target
                rungobuster = tinput(f"{bcolors.BLUE}[+] Port 443 found on target! Would you like to run gobuster? y/N {bcolors.ENDC}", 30)
                rungobuster = rungobuster.lower()
                if rungobuster == "y":
                    os.system(cmdrungobuster)
                    break
                elif rungobuster == "n":
                    print(f"{bcolors.WARNING}[-] Skipping port 443...")
                    break
                else:
                    print(f"{bcolors.FAIL}[-] ERROR Handling input. Please type y or N.")
            else:
                break
        except TimeoutOccurred:
            catgobusterresults = "cat gobuster443results"
            print(f"\n{bcolors.TIMEOUT}{bcolors.BLK}[*] TIMED OUT: Printing old results, then rerunning scans just in case...{bcolors.ENDC}")
            print(f'{bcolors.BOLD}----------------------------{bcolors.WARNING}OLD RESULTS{bcolors.ENDC}{bcolors.BOLD}----------------------------{bcolors.ENDC}')
            os.system(catgobusterresults)
            print(f'{bcolors.BOLD}---------------------------{bcolors.WARNING}END OF RESULTS{bcolors.ENDC}{bcolors.BOLD}--------------------------{bcolors.ENDC}')
            print(gobustertextprint)
            os.system(cmdrungobuster)
            break



def fullscan(): # Scan all TCP ports, if any are found, run a thorough scan with vulners script as well as default scripts & gobuster.
    global quickscancmd
    texttoprint = f"\n{bcolors.BOLD}[*] Running scan type: Full{bcolors.ENDC}"
    catfullfile = "cat nmap/fullscan.nmap"
    parsequickfile = "cat nmap/quickscan.nmap | grep 'open\\|filtered' | cut -d \" \" -f 1 | cut -d \"/\" -f 1 | tr \"\\n\" \",\" | head -c-1 > nmap/parsedquickscan.txt" # Command to parse quickscan file. 
    if os.path.isfile("nmap/quickscan.nmap"):
        print(f"{bcolors.WARNING}[*] Old quickscan results have been found! Parsing data for full scan...")
        os.system(parsequickfile)
        f = open("nmap/parsedquickscan.txt", "r")
        if f.mode == "r":
            quickscanopenports = f.read()
        f.close()
        cmd = "nmap -Pn -p %s -sV -oA nmap/fullscan %s" %(quickscanopenports, target) # fullscancmd: -sV seems to trigger vulners script.
        # sudo nmap --script "vuln" -p21,22,80 192.168.167.107 <-- This worked.

    elif not os.path.isfile("nmap/quickscan.nmap"):

        print(f"{bcolors.WARNING}\n[*] No old quick scan results found, running now to parse...{bcolors.ENDC}")
        os.system(quickscancmd)
        os.system(parsequickfile)
        print(f"{bcolors.GREEN}\n[+] Scan completed & parsed, starting full scan now...{bcolors.ENDC}")
        f = open("nmap/parsedquickscan.txt", "r")
        if f.mode == "r":
            quickscanopenports = f.read()
        f.close()

        # This command is repeated twice in this function. Is this necessary?
        cmd = "nmap -Pn -p %s -sV -oA nmap/fullscan %s" % (quickscanopenports, target) # Maybe make this var global?

    else:
        print(f"{bcolors.FAIL}Error occured while checking if quickscan results were available.")
        pass
    while fullscan_results_available:
        try:
            print(f"{bcolors.WARNING}[*] Previous scan files have been found in nmap dir!{bcolors.ENDC}\n")
            rerun_scan = tinput(f"{bcolors.BOLD}[*] Would you like to rerun the full scan? y/N {bcolors.ENDC}", 30)
            rerun_scan = rerun_scan.lower()
            if rerun_scan == "y":
                print(texttoprint)
                os.system(cmd) # Add command to run vuln scan here
                break

            elif rerun_scan == "n":
                print(f"{bcolors.WARNING}[*] Scan rerun denied by user. Printing old results instead.{bcolors.ENDC}")
                os.system(catfullfile)
                break

            else:
                print(f"{bcolors.FAIL}[-] Error! Please use either Y or N to signify your response!{bcolors.ENDC}")


        except TimeoutOccurred:
            print(f"\n{bcolors.TIMEOUT}{bcolors.BLK}[*] TIMED OUT: Printing old results, then rerunning scans just in case...{bcolors.ENDC}")
            print(f'{bcolors.BOLD}----------------------------{bcolors.WARNING}OLD RESULTS{bcolors.ENDC}{bcolors.BOLD}----------------------------{bcolors.ENDC}')
            os.system(catfullfile)
            print(f'{bcolors.BOLD}---------------------------{bcolors.WARNING}END OF RESULTS{bcolors.ENDC}{bcolors.BOLD}--------------------------{bcolors.ENDC}')
            print(texttoprint)
            os.system(cmd) # Add command to run vuln scan here
            break

    while not fullscan_results_available:
        print(texttoprint)
        os.system(cmd) # Add command to run vuln scan here
        break

    gobusterscan()



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
elif scan_type == "gobuster" or scan_type == "g":
    gobusterscan()
elif scan_type == "vuln" or scan_type == "vulnscan" or scan_type == "v":
    vulnscan()