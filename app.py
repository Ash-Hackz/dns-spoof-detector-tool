import socket
import random
import http.client
import ssl
import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
from tkinter import filedialog
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import threading
import dns.name
import dns.rdatatype
import dns.dnssec
import dns.resolver
import dns.query
import dns.message
import pyperclip
from datetime import datetime, timezone
import requests
import time
import concurrent.futures


class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        widget.bind("<Enter>", self.show_tip)
        widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        if self.tipwindow or not self.text:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.geometry(f"+{x}+{y}")
        label = tk.Label(
            tw, text=self.text, justify=tk.LEFT,
            background="#6272a4", relief=tk.SOLID, borderwidth=1,
            font=("tahoma", "8", "normal"), foreground="#f8f8f2"
        )
        label.pack(ipadx=1)

    def hide_tip(self, event=None):
        if self.tipwindow:
            self.tipwindow.destroy()
            self.tipwindow = None

# Global variables
detection_cancelled = False
spinner_running = False
executor = ThreadPoolExecutor(max_workers=5)

# Dracula color scheme
DRACULA_BG = "#282a36"
DRACULA_FG = "#f8f8f2"
DRACULA_SELECTION = "#44475a"
DRACULA_COMMENT = "#6272a4"
DRACULA_CYAN = "#8be9fd"
DRACULA_GREEN = "#50fa7b"
DRACULA_ORANGE = "#ffb86c"
DRACULA_PINK = "#ff79c6"
DRACULA_PURPLE = "#bd93f9"
DRACULA_RED = "#ff5555"
DRACULA_YELLOW = "#f1fa8c"

def cancel_detection():
    global detection_cancelled
    detection_cancelled = True
    log_box.insert(tk.END, "🛑 Detection cancelled.\n", "warn")
    stop_loading_spinner()

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_dns_server(dns_server):
    try:
        ipaddress.ip_address(dns_server)
        return True
    except ValueError:
        return False
    
def get_geoip_info(ip):
    try:
        response = requests.get(f"http://ipinfo.io/{ip}/json", timeout=5)
        data = response.json()
        geo_info = {
            'city': data.get('city', 'Unknown'),
            'region': data.get('region', 'Unknown'),
            'country': data.get('country', 'Unknown'),
            'org': data.get('org', 'Unknown')
        }
        return geo_info
    except requests.exceptions.RequestException:
        return None
    
def check_dnsbl(ip):
    if not is_valid_ip(ip) or ipaddress.ip_address(ip).is_private:
        return "⚠️ Skipping DNSBL check for private or invalid IP.\n"
    
    reversed_ip = '.'.join(reversed(ip.split('.')))
    dnsbls = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "b.barracudacentral.org",
        "dnsbl-1.uceprotect.net"
    ]
    
    listed = []
    for dnsbl in dnsbls:
        query = f"{reversed_ip}.{dnsbl}"
        try:
            dns.resolver.resolve(query, 'A')
            listed.append(dnsbl)
        except dns.resolver.NXDOMAIN:
            continue
        except Exception:
            continue
    
    if listed:
        return f"🚫 IP is listed in DNSBLs: {', '.join(listed)}\n"
    else:
        return f"✅ IP is NOT listed in known DNSBLs\n"

def read_name(response, offset):
    labels = []
    jumped = False
    original_offset = offset
    while True:
        length = response[offset]
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            pointer = ((length & 0x3F) << 8) | response[offset + 1]
            offset = pointer
            jumped = True
            continue
        if length == 0:
            offset += 1
            break
        offset += 1
        labels.append(response[offset:offset + length].decode('utf-8'))
        offset += length
    return '.'.join(labels), original_offset if jumped else offset

def create_dns_query(query, record_type, dnssec=False):
    transaction_id = random.randint(0, 65535)
    flags = 0x0100
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 1 if dnssec else 0

    query_bytes = bytearray()
    query_bytes.extend(transaction_id.to_bytes(2, 'big'))
    query_bytes.extend(flags.to_bytes(2, 'big'))
    query_bytes.extend(questions.to_bytes(2, 'big'))
    query_bytes.extend(answer_rrs.to_bytes(2, 'big'))
    query_bytes.extend(authority_rrs.to_bytes(2, 'big'))
    query_bytes.extend(additional_rrs.to_bytes(2, 'big'))

    for label in query.split('.'):
        query_bytes.append(len(label))
        query_bytes.extend(label.encode())
    query_bytes.append(0)

    record_types = {
        'A': 1, 'AAAA': 28, 'MX': 15, 'CNAME': 5,
        'NS': 2, 'PTR': 12, 'TXT': 16, 'SOA': 6, 'SRV': 33
    }
    query_bytes.extend(record_types[record_type].to_bytes(2, 'big'))
    query_bytes.extend((1).to_bytes(2, 'big'))

    if dnssec:
        query_bytes.append(0)
        query_bytes.extend((41).to_bytes(2, 'big'))
        query_bytes.extend((4096).to_bytes(2, 'big'))
        query_bytes.extend((0).to_bytes(1, 'big'))
        query_bytes.extend((0).to_bytes(1, 'big'))
        query_bytes.extend((1 << 15).to_bytes(2, 'big'))
        query_bytes.extend((0).to_bytes(2, 'big'))

    return query_bytes

def resolve_dns(query, dns_server, record_type, timeout):
    try:
        family = socket.AF_INET6 if force_ipv6_var.get() else (socket.AF_INET6 if ":" in dns_server else socket.AF_INET)
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        data = create_dns_query(query, record_type, dnssec=True)

        sock.sendto(data, (dns_server, 53))
        response, _ = sock.recvfrom(512)
        sock.close()
        return response
    except socket.gaierror as e:
        print(f"DNS query failed. Error: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error during DNS query to {dns_server}: {e}")
        return None

def parse_dns_response(response, record_type, verbose):
    try:
        if len(response) < 12:
            raise ValueError("Incomplete DNS response received.")
        offset = 12
        _, offset = read_name(response, offset)
        offset += 4

        num_answers = int.from_bytes(response[6:8], byteorder='big')
        if num_answers == 0:
            return None
        answers = []
        for _ in range(num_answers):
            name, offset = read_name(response, offset)
            rtype = int.from_bytes(response[offset:offset + 2], byteorder='big')
            ttl = int.from_bytes(response[offset + 4:offset + 8], byteorder='big')
            rdlength = int.from_bytes(response[offset + 8:offset + 10], byteorder='big')
            rdata_offset = offset + 10

            if rtype == 1:  # A
                ip = '.'.join(str(b) for b in response[rdata_offset:rdata_offset + 4])
                answers.append(ip)
            elif rtype == 28:  # AAAA
                raw = response[rdata_offset:rdata_offset + 16]
                ip = str(ipaddress.IPv6Address(raw))
                answers.append(ip)
            elif rtype == 5:  # CNAME
                cname, _ = read_name(response, rdata_offset)
                answers.append(f"CNAME: {cname}")
            elif rtype == 15:  # MX
                preference = int.from_bytes(response[rdata_offset:rdata_offset + 2], byteorder='big')
                exchange, _ = read_name(response, rdata_offset + 2)
                answers.append(f"MX: {preference} {exchange}")
            elif rtype == 2:  # NS
                ns, _ = read_name(response, rdata_offset)
                answers.append(f"NS: {ns}")
            elif rtype == 12:  # PTR
                ptr, _ = read_name(response, rdata_offset)
                answers.append(f"PTR: {ptr}")
            elif rtype == 16:  # TXT
                txt = response[rdata_offset:rdata_offset + rdlength].decode('utf-8')
                answers.append(f"TXT: {txt}")
            elif rtype == 6:  # SOA
                mname, _ = read_name(response, rdata_offset)
                rname, _ = read_name(response, rdata_offset + len(mname) + 2)
                serial = int.from_bytes(response[rdata_offset + len(mname) + len(rname) + 4: rdata_offset + len(mname) + len(rname) + 8], byteorder='big')
                refresh = int.from_bytes(response[rdata_offset + len(mname) + len(rname) + 8: rdata_offset + len(mname) + len(rname) + 12], byteorder='big')
                retry = int.from_bytes(response[rdata_offset + len(mname) + len(rname) + 12: rdata_offset + len(mname) + len(rname) + 16], byteorder='big')
                expire = int.from_bytes(response[rdata_offset + len(mname) + len(rname) + 16: rdata_offset + len(mname) + len(rname) + 20], byteorder='big')
                minimum = int.from_bytes(response[rdata_offset + len(mname) + len(rname) + 20: rdata_offset + len(mname) + len(rname) + 24], byteorder='big')
                answers.append(f"SOA: MNAME={mname}, RNAME={rname}, SERIAL={serial}, REFRESH={refresh}, RETRY={retry}, EXPIRE={expire}, MINIMUM={minimum}")
            elif rtype == 33:  # SRV
                priority = int.from_bytes(response[rdata_offset:rdata_offset + 2], byteorder='big')
                weight = int.from_bytes(response[rdata_offset + 2:rdata_offset + 4], byteorder='big')
                port = int.from_bytes(response[rdata_offset + 4:rdata_offset + 6], byteorder='big')
                target, _ = read_name(response, rdata_offset + 6)
                answers.append(f"SRV: Priority={priority}, Weight={weight}, Port={port}, Target={target}")

            offset = rdata_offset + rdlength

        valid_ips = [ip for ip in answers if is_valid_ip(ip)]
        return valid_ips if valid_ips else None

    except Exception as e:
        print(f"Error parsing DNS response: {e}")
        return None

def detect_spoofing(domain, dns_servers, record_type, verbose, dnssec_enabled, timeout, log=None, progress=None):
    all_ips = []
    results = {}

    total_servers = len(dns_servers)
    for idx, server in enumerate(dns_servers):
        if detection_cancelled:
            if log:
                log.insert(tk.END, "🛑 Detection cancelled. Stopping further queries.\n", "warn")
                break
        if log:
            log.insert(tk.END, f"Querying {server}...\n")
        
        if progress:
            progress['value'] = (idx + 1) / total_servers * 100
            progress.update()

            if dnssec_enabled:
                validate_dnssec(domain, record_type, server, log, verbose=verbose)
        
        if not is_valid_dns_server(server):
            if log:
                log.insert(tk.END, f"❌ Invalid DNS Server IP: {server}\n", "warn")
            continue

        try:
            response = resolve_dns(domain, server, record_type, timeout)
            if response:
                ips = parse_dns_response(response, record_type, verbose)
                if ips:
                    for ip in ips:
                        results.setdefault(ip, []).append(server)
                        all_ips.append(ip)
                else:
                    if log:
                        log.insert(tk.END, f"No valid records from {server}\n")
            else:
                if log:
                    log.insert(tk.END, f"Failed to get response from {server}\n")
        except socket.gaierror as e:
            if log:
                log.insert(tk.END, f"❌ DNS server {server} is unreachable: {e}\n", "warn")
        except socket.timeout:
            if log:
                log.insert(tk.END, f"❌ DNS server {server} timed out.\n", "warn")
        except Exception as e:
            if log:
                log.insert(tk.END, f"❌ Unexpected error with server {server}: {e}\n", "warn")

        if detection_cancelled:
            if log:
                log.insert(tk.END, "🛑 Detection cancelled. Stopping further queries.\n", "warn")
            break

    if len(results) > 1:
        if log:
            log.insert(tk.END, "\n⚠️ Possible DNS Spoofing Detected!\n", "warn")
            for ip, servers in results.items():
                log.insert(tk.END, f"{ip} was returned by: {', '.join(servers)}\n")
    elif results:
        if log:
            log.insert(tk.END, "✅ All servers returned consistent results.\n", "ok")
            for ip in results:
                log.insert(tk.END, f"Result: {ip}\n")
    else:
        if log:
            log.insert(tk.END, "❌ No valid DNS response received.\n", "warn")

    if all_ips:
        return Counter(all_ips).most_common(1)[0][0]
    return None

def validate_dnssec(domain, record_type, dns_server, log=None, verbose=False):
    try:
        domain_name = dns.name.from_text(domain)
        query = dns.message.make_query(domain_name, getattr(dns.rdatatype, record_type), want_dnssec=True)
        response = dns.query.udp(query, dns_server, timeout=5)

        rrset = None
        rrsig = None
        for answer in response.answer:
            if answer.rdtype == getattr(dns.rdatatype, record_type):
                rrset = answer
            elif answer.rdtype == dns.rdatatype.RRSIG:
                rrsig = answer

        if not rrset or not rrsig:
            if log:
                log.insert(tk.END, f"🔍 No DNSSEC data returned from {dns_server} for {domain}\n", "warn")
            return False
     
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        key_response = resolver.resolve(domain, 'DNSKEY')
    except Exception as e:
        if log:
            log.insert(tk.END, f"❌ DNSKEY fetch error: {e}\n", "warn")
        return False

    for rr in key_response.response.answer:
        if rr.rdtype == dns.rdatatype.DNSKEY:
                try:
                    dns.dnssec.validate(rrset, rrsig, {domain_name: rr})
                    if log:
                        log.insert(tk.END, f"✅ DNSSEC validation succeeded for {domain} on {dns_server}\n", "ok")

                        if verbose:
                            for sig in rrsig:
                                log.insert(tk.END, f"🔑 RRSIG Info:\n", "ok")
                                log.insert(tk.END, f"    Signer Name : {sig.signer}\n")
                                log.insert(tk.END, f"    Algorithm   : {dns.dnssec.algorithm_to_text(sig.algorithm)} ({sig.algorithm})\n")
                                log.insert(tk.END, f"    Key Tag     : {sig.key_tag}\n")
                                log.insert(tk.END, f"    Valid From  : {datetime.fromtimestamp(sig.inception, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
                                log.insert(tk.END, f"    Valid Until : {datetime.fromtimestamp(sig.expiration, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n")

                    return True
                except dns.dnssec.ValidationFailure as e:
                    if log:
                        log.insert(tk.END, f"❌ DNSSEC validation failed on {dns_server}: {e}\n", "warn")
                    return False
                except Exception as e:
                    if log:
                        log.insert(tk.END, f"❌ DNSSEC validation error on {dns_server}: {e}\n", "warn")
                    return False

def reverse_lookup(ip):
    try:
        rev_name = dns.reversename.from_address(ip)
        answer = dns.resolver.resolve(rev_name, 'PTR')
        return ', '.join(str(r) for r in answer)
    except Exception as e:
        return f"❌ PTR lookup failed: {e}"

def check_website_availability(ip, domain, ports=[443, 80, 8080, 8443], timeout=3):
    if ipaddress.ip_address(ip).is_private:
        return False
    for port in ports:
        try:
            if port == 443:
                conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ssl.create_default_context())
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=timeout)
            conn.request("GET", "/", headers={"Host": domain})
            res = conn.getresponse()
            if res.status == 200:
                return port
        except (http.client.HTTPException, ssl.SSLError, socket.timeout, ConnectionRefusedError):
            continue
    return None

def run_geoip_check(resolved_ip):
    geo_info = get_geoip_info(resolved_ip)
    if geo_info:
        return f"🌍 GeoIP Info: {geo_info['city']}, {geo_info['region']}, {geo_info['country']} ({geo_info['org']})\n"
    else:
        return f"❌ Failed to retrieve GeoIP info for {resolved_ip}\n"

def run_website_availability_check(resolved_ip, domain):
    if is_valid_ip(resolved_ip):
        available = check_website_availability(resolved_ip, domain)
        if available:
            return f"✅ Website {domain} is available at {resolved_ip} (Port {available})\n"
        else:
            return f"❌ Website {domain} is NOT available at {resolved_ip}\n"
    else:
        return f"❌ Resolved IP {resolved_ip} is not a valid IP. Skipping availability check.\n"
    
def run_ip_checks_thread(resolved_ip, domain, log_box, progress):
    global detection_cancelled
    try:
        futures = []
        futures.append(executor.submit(reverse_lookup, resolved_ip))
        futures.append(executor.submit(run_geoip_check, resolved_ip))
        futures.append(executor.submit(run_website_availability_check, resolved_ip, domain))
        futures.append(executor.submit(check_dnsbl, resolved_ip))

        for future in futures:
            try:
                result = future.result()
                root.after(0, lambda res=result: log_box.insert(tk.END, res, "ok" if "✅" in res or "🌍" in res else "warn"))
            except Exception as e:
                root.after(0, lambda err=str(e): log_box.insert(tk.END, f"Error: {err}\n", "warn"))
    finally:
        root.after(0, stop_loading_spinner)

def save_log():
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        title="Save Log As"
    )
    if file_path:
        try:
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(log_box.get("1.0", tk.END))
            messagebox.showinfo("Success", f"Log saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save log:\n{e}")

def copy_to_clipboard():
    try:
        content = log_box.get("1.0", tk.END)
        pyperclip.copy(content)
        messagebox.showinfo("Success", "Log copied to clipboard!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to copy log to clipboard:\n{e}")

def start_loading_spinner():
    global spinner_running
    if spinner_running: return
    spinner_running = True
    spinner_text.set("Loading")
    spinner_frame.grid(row=7, column=0, columnspan=3, padx=10, pady=10)
    animate_spinner()
    
def stop_loading_spinner():
    global spinner_running
    spinner_running = False
    spinner_frame.grid_forget()

def animate_spinner():
    if not spinner_running:
        return
    spinner_text.set(spinner_text.get() + ".")
    if len(spinner_text.get()) > 10:
        spinner_text.set("Loading")
    root.after(300, animate_spinner)

def run_detection():
    domain = domain_entry.get().strip()
    record_type = record_type_var.get()
    verbose = verbose_var.get()
    dnssec_enabled = dnssec_var.get()
    global detection_cancelled
    detection_cancelled = False

    dns_servers = [ip.strip() for ip in dns_entry.get().split(',')] if dns_entry.get() else ['8.8.8.8', '1.1.1.1']
    default_timeout = 5.0

    try:
        timeout = float(timeout_entry.get())
    except ValueError:
        timeout = default_timeout
        messagebox.showwarning("Warning", f"Invalid timeout input. Using default: {default_timeout}s")
        return

    log_box.delete(1.0, tk.END)
    progress['value'] = 0
    start_loading_spinner()

    if check_ip_var.get():
        resolved_ip = domain
        if not is_valid_ip(resolved_ip):
            messagebox.showerror("Invalid IP", f"'{resolved_ip}' is not a valid IP address.")
            stop_loading_spinner()
            return
        log_box.insert(tk.END, f"🔍 Performing checks directly on IP: {resolved_ip}\n", "ok")
        thread = threading.Thread(
            target=run_ip_checks_thread,
            args=(resolved_ip, domain, log_box, progress)
        )
        thread.start()
        return

    log_box.insert(tk.END, f"🔍 Starting DNS Spoofing Detection for domain: {domain}\n", "ok")

    thread = threading.Thread(
        target=run_detection_thread,
        args=(domain, dns_servers, record_type, verbose, dnssec_enabled, timeout, log_box, progress)
    )
    thread.start()

def run_detection_thread(domain, dns_servers, record_type, verbose, dnssec_enabled, timeout, log_box, progress):
    if force_ipv6_var.get():
        dns.resolver.get_default_resolver().use_ipv6 = True
    else:
        dns.resolver.get_default_resolver().use_ipv6 = False
    resolved_ip = None
    try:
        resolved_ip = detect_spoofing(domain, dns_servers, record_type, verbose, dnssec_enabled, timeout, log_box, progress)
    except Exception as e:
        log_box.insert(tk.END, f"Error during detection: {str(e)}\n", "warn")
    finally:
        root.after(0, stop_loading_spinner)

    if resolved_ip:
        futures = []
        futures.append(executor.submit(reverse_lookup, resolved_ip))
        futures.append(executor.submit(run_geoip_check, resolved_ip))
        futures.append(executor.submit(run_website_availability_check, resolved_ip, domain))
        futures.append(executor.submit(check_dnsbl, resolved_ip))
        
        for i, future in enumerate(futures, start=1):
            try:
                result = future.result()
                root.after(0, lambda res=result: log_box.insert(tk.END, res, "ok" if "✅" in res or "🌍" in res else "warn"))
            except Exception as e:
                root.after(0, lambda err=str(e): log_box.insert(tk.END, f"Error: {err}\n", "warn"))
            finally:
                root.after(0, lambda val=i: progress.config(value=val * 25))

def toggle_dark_mode():
    if dark_mode_var.get():
        # Apply Dracula theme
        root.configure(bg=DRACULA_BG)
        style = ttk.Style()
        style.theme_use("clam")

        # Configure styles for Dracula
        style.configure(".", background=DRACULA_BG, foreground=DRACULA_FG)
        style.configure("TFrame", background=DRACULA_BG)
        style.configure("TLabel", background=DRACULA_BG, foreground=DRACULA_FG)
        style.configure("TButton", 
                       background=DRACULA_SELECTION, 
                       foreground=DRACULA_FG,
                       bordercolor=DRACULA_PURPLE,
                       borderwidth=1,
                       relief="solid")
        style.map("TButton",
                 background=[("active", DRACULA_COMMENT)],
                 foreground=[("active", DRACULA_FG)])
        style.configure("TEntry", 
                       fieldbackground=DRACULA_SELECTION,
                       foreground=DRACULA_FG,
                       insertcolor=DRACULA_FG,
                       bordercolor=DRACULA_PURPLE)
        style.configure("TCheckbutton", 
                       background=DRACULA_BG, 
                       foreground=DRACULA_FG,
                       indicatorbackground=DRACULA_SELECTION)
        style.map("TCheckbutton",
                 background=[("active", DRACULA_BG)],
                 foreground=[("active", DRACULA_FG)])
        style.configure("TCombobox", 
                       fieldbackground=DRACULA_SELECTION,
                       background=DRACULA_SELECTION,
                       foreground=DRACULA_FG)
        style.configure("Horizontal.TProgressbar", 
                       thickness=20, 
                       troughcolor=DRACULA_COMMENT, 
                       background=DRACULA_GREEN)

        # Configure the log box
        log_box.configure(
            background=DRACULA_SELECTION,
            foreground=DRACULA_FG,
            insertbackground=DRACULA_FG
        )

        # Configure tags for log colors
        log_box.tag_config("ok", foreground=DRACULA_GREEN)
        log_box.tag_config("warn", foreground=DRACULA_RED)
        log_box.tag_config("info", foreground=DRACULA_CYAN)
        log_box.tag_config("ts", foreground=DRACULA_COMMENT)

        # Configure spinner
        spinner_label.configure(foreground=DRACULA_PURPLE)

        # Configure tooltips (handled in ToolTip class)

    else:
        # Reset to light mode
        root.configure(bg="SystemButtonFace")
        style = ttk.Style()
        style.theme_use("default")

        # Reset all widgets to default colors
        for widget in root.winfo_children():
            try:
                widget.configure(background="SystemButtonFace", foreground="black")
            except:
                pass

        # Reset log box
        log_box.configure(background="white", foreground="black", insertbackground="black")
        log_box.tag_config("ok", foreground="green")
        log_box.tag_config("warn", foreground="red")
        log_box.tag_config("info", foreground="blue")
        log_box.tag_config("ts", foreground="grey")

        # Reset spinner
        spinner_label.configure(foreground="blue")

# Main GUI Setup
root = tk.Tk()
root.title("🚨 DNS Spoofing Detector")
root.geometry("850x650")
root.resizable(True, True)

# Variables
check_ip_var = tk.BooleanVar()
record_type_var = tk.StringVar(value="A")
verbose_var = tk.BooleanVar()
dnssec_var = tk.BooleanVar()
force_ipv6_var = tk.BooleanVar()
dark_mode_var = tk.BooleanVar(value=True)  # Default to dark mode

# Style
style = ttk.Style()
style.theme_use("default")

# Input Frame
input_frame = ttk.Frame(root, padding=10)
input_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
input_frame.columnconfigure((0, 1, 2), weight=1)

# Domain
ttk.Label(input_frame, text="🌐 Domain:").grid(row=0, column=0, sticky="w")
domain_entry = ttk.Entry(input_frame, width=40)
domain_entry.grid(row=0, column=1, sticky="ew")

# Check IP mode
tt = ttk.Checkbutton(input_frame, text="Check IP directly", variable=check_ip_var)
tt.grid(row=0, column=2, sticky="w")
ToolTip(tt, "Use this to analyze an IP address instead of a domain")

# DNS Servers
ttk.Label(input_frame, text="📡 DNS Servers:").grid(row=1, column=0, sticky="w")
dns_entry = ttk.Entry(input_frame)
dns_entry.insert(0, "8.8.8.8, 1.1.1.1")
dns_entry.grid(row=1, column=1, sticky="ew")
ToolTip(dns_entry, "Comma-separated DNS servers")

# Record Type
ttk.Label(input_frame, text="📁 Record Type:").grid(row=2, column=0, sticky="w")
record_dropdown = ttk.Combobox(input_frame, textvariable=record_type_var,
    values=["A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT", "SOA", "SRV"], width=10)
record_dropdown.grid(row=2, column=1, sticky="w")
ToolTip(record_dropdown, "Choose DNS record type")

# Timeout
ttk.Label(input_frame, text="⏱ Timeout (s):").grid(row=2, column=2, sticky="e")
timeout_entry = ttk.Entry(input_frame, width=5)
timeout_entry.insert(0, "5")
timeout_entry.grid(row=2, column=3, sticky="w", padx=(100, 0))
ToolTip(timeout_entry, "DNS query timeout")

# Options Frame
options_frame = ttk.Frame(root, padding=(10, 0))
options_frame.grid(row=1, column=0, sticky="ew")

tt = ttk.Checkbutton(options_frame, text="🔍 Detailed Result", variable=verbose_var)
tt.grid(row=0, column=0, padx=5)

tt = ttk.Checkbutton(options_frame, text="🔐 Enable DNSSEC", variable=dnssec_var)
tt.grid(row=0, column=1, padx=5)

tt = ttk.Checkbutton(options_frame, text="🌐 Force IPv6", variable=force_ipv6_var)
tt.grid(row=0, column=2, padx=5)
ToolTip(tt, "Force DNS queries over IPv6")

# Dark Mode Toggle
dark_mode_check = ttk.Checkbutton(root, text="Dark Mode", variable=dark_mode_var, command=toggle_dark_mode)
dark_mode_check.grid(row=0, column=1, pady=5, sticky="w")

executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
log_box = tk.Text(root, height=20, wrap="word", font=("Consolas", 10))
log_box.grid(row=5, column=0, columnspan=3, sticky="nsew", padx=10, pady=10)

output_scrollbar = ttk.Scrollbar(root, command=log_box.yview)
log_box.config(yscrollcommand=output_scrollbar.set)
output_scrollbar.grid(row=5, column=3, sticky='ns', pady=10)

# Buttons Frame
buttons_frame = ttk.Frame(root, padding=(10, 10))
buttons_frame.grid(row=2, column=0, sticky="ew")

run_btn = ttk.Button(buttons_frame, text="🚀 Run Detection", command=run_detection)
run_btn.grid(row=0, column=0, padx=5)

save_btn = ttk.Button(buttons_frame, text="💾 Save Log", command=save_log)
save_btn.grid(row=0, column=1, padx=5)

copy_btn = ttk.Button(buttons_frame, text="📋 Copy Log", command=copy_to_clipboard)
copy_btn.grid(row=0, column=2, padx=5)

cancel_btn = ttk.Button(buttons_frame, text="❌ Cancel", command=cancel_detection)
cancel_btn.grid(row=0, column=3, padx=5)

# Log Output
log_box.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0,10))
log_box.tag_config("warn", foreground="red")
log_box.tag_config("ok", foreground="green")

# Progress bar
progress = ttk.Progressbar(root, orient="horizontal", length=100, mode="determinate")
progress.grid(row=4, column=0, sticky="ew", padx=10, pady=(0,10))

# Spinner
spinner_frame = ttk.Frame(root)
spinner_text = tk.StringVar(value="Loading")
spinner_label = ttk.Label(spinner_frame, textvariable=spinner_text, font=("Segoe UI", 12, "bold"), foreground="blue")
spinner_label.pack()

# Grid weight
root.grid_rowconfigure(3, weight=1)
root.grid_columnconfigure(0, weight=1)

# Bind Return key to run
root.bind("<Return>", lambda event: run_detection())

# Initialize dark mode
toggle_dark_mode()

root.mainloop()