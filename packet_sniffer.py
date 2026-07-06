# Advanced packet sniffer with protocol parsing, filtering, colored output, and logging
import os
import sys
import io
import ctypes
import datetime
import argparse
from collections import defaultdict

# Force UTF-8 on Windows console so non-ASCII packet data never causes a crash
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
else:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, DNS, DNSQR, Raw, conf

# Rich provides colored terminal output and formatted tables
from rich.console import Console
from rich.table import Table
from rich.text import Text

conf.verb = 0

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "packet_log.txt")

# Single shared console — all output goes through this so colors stay consistent
console = Console()
packet_count = 0

# Incremented per packet type; printed as a table when capture ends
stats = defaultdict(int)

# Traffic on these ports is TLS-encrypted — payload is not human-readable
ENCRYPTED_PORTS = {443, 8443, 465, 587, 993, 995, 636, 5061}

# Traffic on these ports is plain HTTP — we attempt full HTTP parsing on it
HTTP_PORTS = {80, 8080, 8000, 8008}

# All standard HTTP request methods used to detect the start of an HTTP request
HTTP_METHODS = {
    b"GET", b"POST", b"PUT", b"DELETE",
    b"PATCH", b"HEAD", b"OPTIONS", b"CONNECT", b"TRACE"
}


# ── Color legend ──────────────────────────────────────────────────────────────
#   green   = HTTP request/response
#   cyan    = DNS query
#   yellow  = plain TCP (no payload match)
#   white   = UDP
#   magenta = ICMP / ICMPv6
#   dim     = encrypted or binary payloads
# ─────────────────────────────────────────────────────────────────────────────


def is_admin():
    try:
        if hasattr(ctypes, "windll"):
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        get_euid = getattr(os, "geteuid", None)
        return get_euid() == 0 if get_euid else False
    except Exception:
        return False


def log(message, style=None):
    """
    Print a timestamped line to the terminal (with optional rich color style)
    and append the same plain text to the log file.

    markup=False stops rich from misreading brackets in URLs or payloads as
    color tags — e.g. '[TLS encrypted]' would otherwise crash the renderer.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    plain = f"[{timestamp}] {message}"

    console.print(plain, style=style or "", markup=False)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(plain + "\n")


def parse_http(raw_bytes):
    """
    Try to parse raw TCP payload bytes as an HTTP request or response.

    HTTP request first line:  METHOD /path HTTP/1.1
    HTTP response first line: HTTP/1.1 200 OK

    We read up to 512 bytes — enough to cover the request line and common
    headers (Host, User-Agent) without loading the full body into memory.

    Returns a dict with parsed fields on success, or None if not HTTP traffic.
    """
    try:
        text = raw_bytes[:512].decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        if not lines:
            return None

        first_line = lines[0].strip()
        parts = first_line.split(" ", 2)

        # ── HTTP request ──────────────────────────────────────────────────────
        if len(parts) >= 2 and parts[0].encode() in HTTP_METHODS:
            method  = parts[0]
            path    = parts[1] if len(parts) > 1 else "/"
            version = parts[2] if len(parts) > 2 else ""

            # Walk headers to extract Host and User-Agent.
            # Host tells us the destination domain even when the IP is all we
            # have at the network layer (virtual hosting / CDN scenarios).
            host       = ""
            user_agent = ""
            for line in lines[1:]:
                low = line.lower()
                if low.startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                elif low.startswith("user-agent:"):
                    # Truncate long UA strings so the log line stays readable
                    user_agent = line.split(":", 1)[1].strip()[:80]
                if host and user_agent:
                    break

            return {
                "type":       "request",
                "method":     method,
                "path":       path,
                "host":       host,
                "version":    version,
                "user_agent": user_agent,
            }

        # ── HTTP response ─────────────────────────────────────────────────────
        if first_line.startswith("HTTP/"):
            status_code = parts[1] if len(parts) > 1 else "?"
            status_text = parts[2] if len(parts) > 2 else ""
            return {"type": "response", "status_code": status_code, "status_text": status_text}

        return None  # Payload does not look like HTTP

    except Exception:
        return None


def decode_payload(raw_bytes, sport=0, dport=0):
    """
    Decode raw TCP/UDP payload for display.

    Returns a short human-readable preview string.
    Binary-heavy payloads (>40% non-printable chars) are summarised by size
    instead of being dumped as garbage characters.
    """
    if sport in ENCRYPTED_PORTS or dport in ENCRYPTED_PORTS:
        return f"[TLS encrypted — {len(raw_bytes)} bytes]"
    try:
        text    = raw_bytes[:60].decode("utf-8", errors="replace")
        cleaned = "".join(c if c.isprintable() else "?" for c in text)
        if len(cleaned) > 0 and cleaned.count("?") / len(cleaned) > 0.4:
            return f"[binary data — {len(raw_bytes)} bytes]"
        return cleaned.replace("\n", " ").replace("\r", "")
    except Exception:
        return f"[binary — {len(raw_bytes)} bytes]"


def handle_tcp(src, dst, packet, ip_version="4"):
    """
    Handle a TCP packet for either IPv4 or IPv6.

    Priority order for display:
      1. If port matches HTTP_PORTS and parse_http succeeds → show HTTP details
      2. Otherwise → show raw TCP info with payload preview
    """
    sport = packet[TCP].sport
    dport = packet[TCP].dport
    flags = packet[TCP].flags
    stats["tcp"] += 1

    prefix = "HTTP " if ip_version == "4" else "HTTP6 "
    tcp_prefix = "TCP  " if ip_version == "4" else "TCP6 "

    # ── Attempt HTTP parsing first ────────────────────────────────────────────
    if packet.haslayer(Raw) and (sport in HTTP_PORTS or dport in HTTP_PORTS):
        http = parse_http(packet[Raw].load)
        if http:
            stats["http"] += 1
            if http["type"] == "request":
                host_part = f"  host={http['host']}" if http["host"] else ""
                ua_part   = f"  ua={http['user_agent']}" if http["user_agent"] else ""
                info = (
                    f"{prefix}{src}:{sport} -> {dst}:{dport}  "
                    f"{http['method']} {http['path']}{host_part}{ua_part}"
                )
                log(info, style="green")
            else:
                info = (
                    f"{prefix}{src}:{sport} -> {dst}:{dport}  "
                    f"Response {http['status_code']} {http['status_text']}"
                )
                log(info, style="bright_green")
            return

    # ── Fallback: plain TCP display ───────────────────────────────────────────
    info  = f"{tcp_prefix}{src}:{sport} -> {dst}:{dport}  flags={flags}"
    style = "yellow"

    if packet.haslayer(Raw):
        payload_text = decode_payload(packet[Raw].load, sport, dport)
        if "TLS encrypted" in payload_text:
            stats["encrypted"] += 1
            style = "dim"
        info += f"  payload=\"{payload_text}\""

    log(info, style=style)


def handle_udp(src, dst, packet, ip_version="4"):
    """Handle a UDP packet. DNS queries get their own dedicated display."""
    sport = packet[UDP].sport
    dport = packet[UDP].dport
    stats["udp"] += 1

    prefix = "UDP  " if ip_version == "4" else "UDP6 "
    info   = f"{prefix}{src}:{sport} -> {dst}:{dport}"

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        stats["dns"] += 1
        # Decode the queried domain name; rstrip removes the trailing root dot
        query = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
        info += f"  DNS query: {query}"
        log(info, style="cyan")
    else:
        log(info, style="white")


def packet_handler(packet):
    global packet_count
    packet_count += 1
    stats["total"] += 1

    # ── IPv4 ──────────────────────────────────────────────────────────────────
    if packet.haslayer(IP):
        src   = packet[IP].src
        dst   = packet[IP].dst
        proto = packet[IP].proto
        stats["ipv4"] += 1

        if packet.haslayer(TCP):
            handle_tcp(src, dst, packet, ip_version="4")
        elif packet.haslayer(UDP):
            handle_udp(src, dst, packet, ip_version="4")
        elif packet.haslayer(ICMP):
            stats["icmp"] += 1
            info = f"ICMP {src} -> {dst}  type={packet[ICMP].type} code={packet[ICMP].code}"
            log(info, style="magenta")
        else:
            stats["other"] += 1
            log(f"IP   {src} -> {dst}  proto={proto}")

    # ── IPv6 ──────────────────────────────────────────────────────────────────
    elif packet.haslayer(IPv6):
        src = packet[IPv6].src
        dst = packet[IPv6].dst
        stats["ipv6"] += 1

        if packet.haslayer(TCP):
            handle_tcp(src, dst, packet, ip_version="6")
        elif packet.haslayer(UDP):
            handle_udp(src, dst, packet, ip_version="6")
        elif packet.haslayer(ICMPv6EchoRequest):
            stats["icmp"] += 1
            log(f"ICMPv6 Echo {src} -> {dst}", style="magenta")
        else:
            stats["other"] += 1
            log(f"IPv6 {src} -> {dst}")

    else:
        return  # Non-IP traffic (ARP, etc.) — skip silently


def print_summary():
    """
    Print a protocol breakdown table using rich at the end of the capture.

    Shows count and percentage-of-total for every tracked protocol so you
    can see at a glance what kind of traffic dominated the capture session.
    """
    console.print("\n" + "-" * 60)
    console.print(f"Capture complete.  Total packets captured: [bold]{packet_count}[/bold]")
    console.print(f"Log saved to: {LOG_FILE}\n")

    table = Table(title="Protocol Summary", show_header=True, header_style="bold white")
    table.add_column("Protocol",   style="bold",  min_width=12)
    table.add_column("Count",      justify="right", min_width=8)
    table.add_column("% of Total", justify="right", min_width=10)

    total = stats["total"] or 1  # guard against division by zero on empty capture

    rows = [
        ("IPv4",      "ipv4",      "cyan"),
        ("IPv6",      "ipv6",      "blue"),
        ("TCP",       "tcp",       "yellow"),
        ("UDP",       "udp",       "white"),
        ("ICMP",      "icmp",      "magenta"),
        ("DNS",       "dns",       "cyan"),
        ("HTTP",      "http",      "green"),
        ("Encrypted", "encrypted", "dim"),
        ("Other",     "other",     "white"),
    ]

    for label, key, color in rows:
        count = stats[key]
        pct   = f"{count / total * 100:.1f}%"
        table.add_row(Text(label, style=color), str(count), pct)

    console.print(table)


def start_sniffing(interface, count, bpf_filter):
    if not is_admin():
        console.print("[red]Error: Run as Administrator (Windows) or root (Linux).[/red]")
        sys.exit(1)

    effective_filter = bpf_filter if bpf_filter.strip() else None

    console.print(f"[bold]Interface :[/bold] {interface}")
    console.print(f"[bold]Count     :[/bold] {count if count else 'unlimited'}")
    console.print(f"[bold]Filter    :[/bold] {effective_filter or 'none'}")
    console.print(f"[bold]Log file  :[/bold] {LOG_FILE}")
    console.print("-" * 60)

    try:
        sniff(
            iface=interface,
            prn=packet_handler,
            count=count,
            filter=effective_filter,
            store=False,
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped by user.[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
    finally:
        print_summary()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Packet Sniffer")
    parser.add_argument("-i", "--interface", default="Wi-Fi",  help="Network interface name (default: Wi-Fi)")
    parser.add_argument("-c", "--count",     type=int, default=0, help="Packets to capture, 0 = unlimited (default: 0)")
    parser.add_argument("-f", "--filter",    default="",       help='BPF filter e.g. "tcp port 80"')
    args = parser.parse_args()

    start_sniffing(args.interface, args.count, args.filter)
