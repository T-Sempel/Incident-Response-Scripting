import subprocess
import re
import time

LOG_FILE = "/var/log/auth.log"  #File path for successful or failed logins on Debian/Ubuntu
ATTEMPT_THRESHOLD = 5           #Number of attempts allowed by any one IP
BLOCK_DURATION = 86400          #One day expressed in seconds

BLOCKED_IP_ADDRESSES = {}       #Dictionary for each blocked address

FAILED_LOGIN_PATTERN = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")      #capture ip address from failed SSH login attempts
FAILED_ATTEMPTS = {}            #Dictionary for logging each ip's failed attempts

def log_failures(ip):                       #Function for tracking the number of failed attempts for the ip
    FAILED_ATTEMPTS.setdefault(ip, 0)       #Set default value to '0'
    FAILED_ATTEMPTS[ip] += 1                

def block_ip(ip):
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)      #use iptables to make rule to block the ip
        BLOCKED_IP_ADDRESSES[ip] = time.time()
        print(f"IP {ip} is blocked from entering: attempt limit reached")
    except subprocess.CalledProcessError as e:          #Check for errors, define as e
        print(f"Error blocking {ip}: {e}")              #Print out an error that blocking the ip had an issue

def unblock_ip(ip):
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)     #use iptables to make rule to unblock the ip
        print(f"IP {ip} is now unblocked from the network")     #Print out a success message
        del BLOCKED_IP_ADDRESSES[ip]                    #Delete the ip from the BLOCKED_IP_ADDRESSES dictionary
    except subprocess.CalledProcessError as e:          #Check for errors, define as e
        print(f"Error unblocking {ip}: {e}")            #Print out an error that blocking the ip had an issue

def check_for_updates():
    with open(LOG_FILE, "r"):       #open the file as read mode
        LOG_FILE.seek(0, 2)         #Find the latest line in /auth.logs

        while True:
            line = LOG_FILE.readline()                      #Initialize line as the defined line *0,2* in LOG_FILE
            if not line:                                    #If there's no logs
                time.sleep(1)                               #Wait one second to refresh function
                continue                                    
            match = FAILED_LOGIN_PATTERN.search(line)       #Search for formatted line in line 11
            if match:                                       #If there's a match,
                ip = match.group(1)                         #Find the parenthesized group in line 11
                log_failures(ip)                            #Call log_failures function
                if FAILED_ATTEMPTS[ip] >= ATTEMPT_THRESHOLD and ip not in BLOCKED_IP_ADDRESSES:     #Check to see if attempts are above threshold
                    block_ip(ip)                            #If so, call the block_ip function to block it

            blocked_time = time.time()                      #Set a variablle to the current time
            for ip in list(BLOCKED_IP_ADDRESSES):
                if blocked_time - BLOCKED_IP_ADDRESSES[ip] > BLOCK_DURATION:            #If the time blocked is greater than threshold, call the unblock function
                    unblock_ip(ip)
