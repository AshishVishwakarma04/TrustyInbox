import json
from termcolor import colored
import requests
from tabulate import tabulate
import email
from tkinter import Tk
from tkinter.filedialog import askopenfilename
import re
import random
import time
import pyfiglet
from termcolor import colored

# List of available colors
colors = ["red", "green", "yellow", "blue", "magenta", "cyan", "white"]

# List of available fonts
fonts = ["slant", "3-d", "3x5", "5lineoblique", "bubble", "digital", "isometric1", "letters", "alligator"]

# Select a random color and font
color = random.choice(colors)
font = random.choice(fonts)

# Create ASCII art for the "TrustyInbox" text with the selected font
ascii_text = pyfiglet.figlet_format("TrustyInbox", font=font)

# Print the ASCII art in the selected color
print(colored(ascii_text, color))

time.sleep(0.5)



# VirusTotal API key
api_key = '5b24ca28f4c27b2363a760e5bb39ee7bb1a3ce5530b538459b756d723c955b64'

# Prompt the user to input URLs separated by comma
urls = input('[+] Enter the URLs to scan separated by comma  > ').split(',')


for url in urls:
    url = url.strip()

    # Submit the URL for analysis to VirusTotal
    params = {'apikey': api_key, 'url': url}
    response = requests.post(
        'https://www.virustotal.com/vtapi/v2/url/scan', data=params)

    # Get the scan ID from the response JSON data
    json_response = response.json()
    scan_id = json_response['scan_id']

    # Retrieve the scan report from VirusTotal
    params = {'apikey': api_key, 'resource': scan_id, 'allinfo': '1'}
    response = requests.get(
        'https://www.virustotal.com/vtapi/v2/url/report', params=params)

    # Parse the response JSON data
    json_response = response.json()

    # Check if the URL is safe or not
    if json_response['response_code'] == 1:
        if json_response['positives'] == 0:
            print('\033[92m' + 'The URL %s is safe!' %
                  url + '\033[0m')  # green color for safe URLs
            status_color = '\033[92m'  # green color for clean engines
        else:
            print('\033[91m' + 'The URL %s is malicious! VirusTotal detected %d malicious engines.' %
                  (url, json_response['positives']) + '\033[0m')  # red color for malicious URLs
            # red color for detected malicious engines
            status_color = '\033[91m'

        # Display the security vendors' analysis
        scans = json_response['scans']
        print('\nSecurity vendors\' analysis for %s:' % url)
        headers = ['Vendor', 'Status', 'Last Updated']
        rows = []
        for vendor, result in scans.items():
            status = 'Malicious' if result['detected'] else 'Clean'
            last_updated = result['update'] if 'update' in result else 'N/A'
            status = status_color + status + '\033[0m'  # apply color to status
            rows.append([vendor, status, last_updated])
        print(tabulate(rows, headers=headers, tablefmt='fancy_grid'))
    else:
        print('Unable to scan the URL %s. Error message: %s' %
              (url, json_response['verbose_msg']))


# ask user to select the .eml file
Tk().withdraw()
filename = askopenfilename()

# open the email file and extract headers
with open(filename, "r") as f:
    msg = email.message_from_file(f)

    email_content = f.read()


sender = msg["From"].split("\n", 3)[:3]
arc_seal = msg["ARC-Seal"].split("\n", 3)[:3]
arc_message_sig = msg["ARC-Message-Signature"].split("\n", 3)[:3]
arc_auth_results = msg["ARC-Authentication-Results"].split("\n", 3)[:3]
dkim_sig = msg["DKIM-Signature"].split("\n", 3)[:3]
received_spf = msg["Received-SPF"].split("\n", 3)[:3]

# display headers with colored text
print(colored("Sender's Mail:", "red"))
print("\n".join(sender))
print()

print(colored("ARC-Seal:", "green"))
print("\n".join(arc_seal))
print()

print(colored("ARC-Message-Signature:", "blue"))
print("\n".join(arc_message_sig))
print()

print(colored("ARC-Authentication-Results:", "magenta"))
print("\n".join(arc_auth_results))
print()

print(colored("DKIM-Signature:", "cyan"))
print("\n".join(dkim_sig))
print()

print(colored("Received-SPF:", "yellow"))
print("\n".join(received_spf))
print()

# extract the IPv6 address from the received header
received_header = msg.get('received')
ipv6_pattern = r'\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
ipv6_address = re.search(ipv6_pattern, received_header).group(0)

print(colored("IPV6 Address", "green"))
print(f"{ipv6_address}")

import enchant
import requests
import json
import tkinter as tk
from tkinter import scrolledtext
from tqdm import tqdm
from termcolor import colored

# Create GUI window
window = tk.Tk()
window.title("Trusty Inbox")
window.geometry("600x600")

# Create scrolled text widget to take input
input_text = scrolledtext.ScrolledText(window, width=80, height=20)
input_text.pack(padx=10, pady=10)

# Define function to check grammar, spelling, and spaces
def check_message():
    # Get input message from scrolled text widget
    message = input_text.get('1.0', 'end-1c')

    # Check for unusual spaces
    if '  ' in message:
        print(colored('Unusual spaces detected!', 'red'))

    # Check for spelling mistakes
    words = message.split()
    misspelled = []
    for word in words:
        if not enchant.Dict("en_US").check(word):
            misspelled.append(word)

    if misspelled:
        print(colored('Spelling mistakes detected!', 'red'))
        for word in misspelled:
            print(colored(f'- {word}', 'red'))

    # Check for grammar mistakes
    url = 'https://languagetool.org/api/v2/check'
    data = {'text': message, 'language': 'auto'}
    response = requests.post(url, data=data)
    json_data = json.loads(response.text)

    grammar_errors = []
    for error in json_data['matches']:
        if error['rule']['category']['id'] == 'grammar':
            grammar_errors.append(error)

    if grammar_errors:
        print(colored('Grammar mistakes detected!', 'red'))
        for error in grammar_errors:
            print(colored(f'- {error["message"]}', 'red'))

    # Calculate score using progress bar
    score = 100
    total_checks = len(words) + len(grammar_errors) + len(misspelled) + int('  ' in message)
    with tqdm(total=total_checks, bar_format='{l_bar}{bar:20}{r_bar}{bar:-10b}') as pbar:
        if '  ' in message:
            score -= 20
            pbar.update(1)
        for word in words:
            if not enchant.Dict("en_US").check(word):
                misspelled.append(word)
                score -= 5
                pbar.update(1)
            else:
                pbar.update(1)
        for error in grammar_errors:
            score -= 10
            pbar.update(1)
        for word in misspelled:
            pbar.update(1)

    print(colored(f'Score: {score}', 'green'))

# Create button to check message
check_button = tk.Button(window, text="Check Message", command=check_message)
check_button.pack(pady=10)

# Start GUI loop
window.mainloop()
