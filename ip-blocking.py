import subprocess
import re
import time
from datetime import datetime

LOG_FILE = "/var/log/auth.log"  #File path for successful or failed logins on Debian/Ubuntu
ATTEMPT_THRESHOLD = 5           #Number of attempts allowed by any one IP
BLOCK_DURATION = 86400          #One day expressed in seconds

BLOCKED_IP_ADDRESSES = {}       #Dictionary for each blocked address

FAILED_LOGIN_PATTERN = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")      #Regex pattern searching in auth.log for failed ssh
ACCEPTED_LOGIN_PATTERN = re.compile(r"Accepted password for .* from (\d+\.\d+\.\d+\.\d+)")  #Regex pattern searching in auth.log for successul ssh
ROOT_LOGIN_PATTERN = re.compile(r"Failed password for root from (\d+\.\d+\.\d+\.\d+)")      #Regex pattern searching in auth.log for failed root login
FAILED_ATTEMPTS = {}        #Dictionary for logging each ip's failed attempts
FAILED_ROOT_LOGIN = {}      #Track FAILED root login attempts for ip's
SUCCESSFUL_ROOT_LOGIN = {}

def log_failures(ip):                       #Function for tracking the number of failed attempts for the ip
    FAILED_ATTEMPTS.setdefault(ip, 0)       #Set default value for ip to '0'
    FAILED_ATTEMPTS[ip] += 1

def log_failed_root(ip):                    #Function for tracking the number of failed attempts for the ip for failed root logins
    FAILED_ROOT_LOGIN.setdefault(ip, 0)     #Set default value for ip to '0'
    FAILED_ROOT_LOGIN[ip] += 1                

def log_successful_root(ip):
    SUCCESSFUL_ROOT_LOGIN.setdefault(ip, 0)
    SUCCESSFUL_ROOT_LOGIN[ip] += 1
    login_time = datetime.now()
    formatted_login_time = login_time.strftime("%Y-%m-%d %H:%M:%S %p")      #Formatted time: YYYY-MM-DD HH:MM:SS AM/PM
    print(f"Successful SSH login from IP: {ip} at {formatted_login_time}")

def block_ip(ip):
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)      #use iptables to make rule to block the ip
        BLOCKED_IP_ADDRESSES[ip] = time.time()          #Initialize start time for blocking ip
        time_blocked = datetime.now()
        formatted_time_blocked = time_blocked.strftime("%Y-%m-%d %H:%M:%S %p")      #Formatted time: YYYY-MM-DD HH:MM:SS AM/PM
        print(f"IP {ip} is blocked from entering: attempt limit reached as of {formatted_time_blocked}")
    except subprocess.CalledProcessError as e:          #Check for errors, define as e
        print(f"Error blocking {ip}: {e}")              #Print out an error that blocking the ip had an issue

def unblock_ip(ip):
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)  #use iptables to make rule to unblock the ip
        time_unblocked = datetime.now()
        formatted_time_unblocked = time_unblocked.strftime("%Y-%m-%d %H:%M:%S %p")               #Formatted time: YYYY-MM-DD HH:MM:SS AM/PM
        print(f"IP {ip} is now unblocked from the network as of {formatted_time_unblocked}")     #Print out a success message
        FAILED_ATTEMPTS[ip] = 0                         #Reset FAILED_ATTEMPTS for a given IP
        del BLOCKED_IP_ADDRESSES[ip]                    #Delete the ip from the BLOCKED_IP_ADDRESSES dictionary
    except subprocess.CalledProcessError as e:          #Check for errors, define as e
        print(f"Error unblocking {ip}: {e}")            #Print out an error that blocking the ip had an issue

def updates():
    with open(LOG_FILE, "r") as log_file:       #open the file as read mode
        log_file.seek(0, 2)                     #Find the latest line in /auth.logs
        last_printed_message = time.time()      #Initialize the last_printed_message as the current time


        SUCCESSFUL_SSH_ATTEMPTS = 0             #Tracks the number of successul ssh logins
        TOTAL_SSH_ATTEMPTS = 0                  #Tracks number of all ssh login attempts (failed or successful)
        FAILED_ROOT_ATTEMPTS = 0                #Tracks the number of failed root login attempts

        while True:
            line = log_file.readline()                      #Initialize line as the defined line *0,2* in LOG_FILE
            if not line:                                    #If there's no logs
                time.sleep(30)                               #Wait one minute to refresh function
                continue

            match = FAILED_LOGIN_PATTERN.search(line)       #Search for formatted line in line 11
            if match:                                       #If there's a match,
                TOTAL_SSH_ATTEMPTS +=1
                ip = match.group(1)                         #Find the parenthesized group in line 11
                log_failures(ip)                            #Call log_failures function
                if FAILED_ATTEMPTS[ip] >= ATTEMPT_THRESHOLD and ip not in BLOCKED_IP_ADDRESSES:     #Check to see if attempts are above threshold
                    block_ip(ip)                            #If so, call the block_ip function to block it

            match = ACCEPTED_LOGIN_PATTERN.search(line)       #Search for formatted line in line 11
            if match:                                       #If there's a match,
                SUCCESSFUL_SSH_ATTEMPTS +=1
                ip = match.group(1)
                log_successful_root(ip)

            match = ROOT_LOGIN_PATTERN.search(line)
            if match:
                FAILED_ROOT_ATTEMPTS += 1
                ip = match.group(1)
                log_failed_root(ip)

                if FAILED_ROOT_LOGIN[ip] >= ATTEMPT_THRESHOLD and ip not in BLOCKED_IP_ADDRESSES:
                    block_ip(ip)

            blocked_time = time.time()                      #Set a variablle to the current time
            for ip in list(BLOCKED_IP_ADDRESSES):
                if blocked_time - BLOCKED_IP_ADDRESSES[ip] > BLOCK_DURATION:            #If the time blocked is greater than threshold, call the unblock function
                    unblock_ip(ip)

            if time.time() - last_printed_message >= 300:   #If the timer is over or equal to 5 minutes
                num_blocked = len(BLOCKED_IP_ADDRESSES)     #Number of IP addresses blocked based off of the length of BLOCKED_IP_ADDRESSES
                print(f"Number of IP addresses blocked: {num_blocked}")    #Print the number of addresses blocked
                print(f"Number of total SSH attempts since last update: {TOTAL_SSH_ATTEMPTS}") #Print the number of ssh attempts for the last 5 minutes
                print(f"Number of failed root login attempts since last update: {FAILED_ROOT_ATTEMPTS}") #Print the number of failed root login attempts for last 5 minutes
                last_printed_message = time.time()
                TOTAL_SSH_ATTEMPTS = 0
                FAILED_ROOT_ATTEMPTS = 0

            time.sleep(1)

if __name__ == "__main__":
    updates()
