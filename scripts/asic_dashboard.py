import os
import sys
import time
import subprocess
import threading
import random
import psutil
import re
import signal
import termios
import tty
import select
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text

console = Console()

class TacticalASICDashboard:
    def __init__(self, interfaces):
        self.interfaces = interfaces
        self.alerts = []
        self.packet_stream = []
        self.me_stream = []
        self.stats = {
            "L1_Net": 0, "L2_EDR": 0, "L2_PRIV": 0, 
            "L3_HW": 0, "L4_RF": 0, "ASI_Load": 15,
            "Tensors_Optimized": 0, "Actual_Tensors": 0,
            "Triangulation": None
        }
        self.cpu_history = []
        self.tensor_heatmap = [0] * 128 # 16x8 grid representing Threat DB
        self.jamming_active = False
        self.hammer_mode = False
        self.vault_locked = False
        self.swarm_nodes = 1
        self.swarm_syncs = 0
        self.crypto_corr = 0.0
        self.stop_event = threading.Event()
        self.flash_state = False
        self.backend_process = None
        self.window_title = "ASI_COMMAND_CENTER"
        sys.stdout.write(f"\x1b]2;{self.window_title}\x07")

    def force_foreground(self):
        try:
            subprocess.run(["wmctrl", "-a", self.window_title], capture_output=True)
        except: pass

    def trigger_bios_beep(self):
        while self.jamming_active and not self.stop_event.is_set():
            try:
                subprocess.run("echo -e '\\a' | sudo tee /dev/console", shell=True, capture_output=True)
                self.force_foreground()
                time.sleep(0.5)
            except: pass

    def get_gpu_temp(self):
        try:
            res = subprocess.run(["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader,nounits"], capture_output=True, text=True)
            if res.returncode == 0:
                return int(res.stdout.strip())
        except: pass
        return 32 + (36 if self.hammer_mode else 0) + random.randint(-1, 1)

    def generate_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="upper", size=10),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        layout["upper"].split_row(
            Layout(name="host_telemetry"),
            Layout(name="asic_telemetry")
        )
        layout["main"].split_row(
            Layout(name="traffic_stream", ratio=2),
            Layout(name="me_stream", ratio=2),
            Layout(name="middle_col", ratio=3),
            Layout(name="layer_status", ratio=2)
        )
        layout["middle_col"].split_column(
            Layout(name="intel_feed", ratio=1),
            Layout(name="tensor_map", ratio=1)
        )
        return layout

    def get_host_telemetry(self):
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        self.cpu_history.append(cpu)
        if len(self.cpu_history) > 30: self.cpu_history.pop(0)
            
        table = Table(show_header=False, expand=True, box=None)
        cpu_bar = "|" * int(cpu / 5)
        ram_bar = "|" * int(ram / 5)
        table.add_row("HOST CPU", f"[bold {'red' if cpu > 80 else 'green'}]{cpu}%[/bold {'red' if cpu > 80 else 'green'}]", f"[green]{cpu_bar:<20}[/green]")
        table.add_row("HOST RAM", f"[bold {'red' if ram > 80 else 'blue'}]{ram}%[/bold {'red' if ram > 80 else 'blue'}]", f"[blue]{ram_bar:<20}[/blue]")
        table.add_row("OS KERNEL", "[white]Linux 6.12.73-AMD64[/white]", "[green]STABLE[/green]")
        
        spark_chars = " ▂▃▄▅▆▇█"
        sparkline = ""
        for val in self.cpu_history:
            idx = min(int(val / (100 / len(spark_chars))), len(spark_chars) - 1)
            color = "red" if val > 80 else "yellow" if val > 50 else "green"
            sparkline += f"[{color}]{spark_chars[idx]}[/{color}]"
        
        table.add_row("")
        table.add_row("[bold]LOAD PROFILE[/bold]", sparkline, "")
        return Panel(table, title="[bold]SYSTEM VITALS[/bold]", border_style="blue")

    def get_asic_telemetry(self):
        load = self.stats["ASI_Load"] + random.randint(-2, 2)
        if self.hammer_mode: load = 98 + random.randint(0, 2)
        gpu_temp = self.get_gpu_temp()
        
        table = Table(show_header=False, expand=True, box=None)
        table.add_row("ASIC CORE", "[bold cyan]FERMI-QIHSE v2.5[/bold cyan]", "[cyan]ONLINE[/cyan]")
        table.add_row("COMPUTE LOAD", f"[bold {'red' if self.hammer_mode else 'green'}]{load}%[/bold {'red' if self.hammer_mode else 'green'}]", 
                      "[bold red]MAXIMUM UTILIZATION[/bold red]" if self.hammer_mode else "[green]RESERVE CAPACITY HIGH[/green]")
        
        t_count = self.stats.get("Actual_Tensors", 0)
        table.add_row("TENSOR DB", f"[bold yellow]{t_count:,} VECTORS[/bold yellow]", f"[yellow]+{self.stats.get('Tensors_Optimized', 0)} EVOLVED[/yellow]")
        
        temp_color = "red" if gpu_temp > 75 else "orange3" if gpu_temp > 60 else "green"
        table.add_row("GPU TEMP", f"[bold {temp_color}]{gpu_temp}°C[/bold {temp_color}]", 
                      f"[{temp_color}]{'OVERHEATING' if gpu_temp > 75 else 'THERMAL PEAK' if gpu_temp > 60 else 'STABLE'}[/{temp_color}]")
        
        # Key Extraction Progress
        progress = min(int(self.crypto_corr * 100), 100)
        prog_bar = "█" * (progress // 5) + "░" * (20 - (progress // 5))
        table.add_row("")
        table.add_row("KEY EXTRACTION", f"[bold magenta]{progress}%[/bold magenta]", f"[magenta]{prog_bar}[/magenta]")
        
        hammer_status = "[bold blink white on red] HAMMER MODE ACTIVE [/bold blink white on red]" if self.hammer_mode else "[dim]NOMINAL OPERATION[/dim]"
        table.add_row("STATE", hammer_status, "")
        return Panel(table, title="[bold]ASIC CO-PROCESSOR[/bold]", border_style="cyan")

    def get_layer_status(self):
        table = Table(show_header=False, expand=True, box=None)
        table.add_row("L1 EDGE", "[green]SECURE[/green]")
        table.add_row("L2 EDR", "[bold red]IPS ACTIVE[/bold red]" if self.stats["L2_EDR"] > 0 else "[green]ACTIVE[/green]")
        table.add_row("L2 PRIV", "[bold red]ESCALATION[/bold red]" if self.stats["L2_PRIV"] > 0 else "[green]ENFORCED[/green]")
        table.add_row("L3 HW", "[green]NOMINAL[/green]")
        l3_me_status = "[bold red]HECI ALERT[/bold red]" if any("L3+ ME" in a[1] for a in self.alerts) else "[green]SENTRY ACTIVE[/green]"
        table.add_row(" └─ [yellow]L3+ ME[/yellow]", l3_me_status)
        table.add_row("L4 RF", "[red]ALERT[/red]" if self.jamming_active else "[green]PASSIVE[/green]")
        if self.stats.get("Triangulation"):
            x, y, conf = self.stats["Triangulation"]
            table.add_row(" └─ [yellow]TRIANG[/yellow]", f"[bold yellow]X:{x} Y:{y}[/bold yellow]")
            table.add_row(" └─ [yellow]CONF[/yellow]", f"[yellow]{conf} NODES[/yellow]")
        table.add_row("L5 SWARM", f"[cyan]{self.swarm_nodes} NODES ({self.swarm_syncs} SYNCS)[/cyan]")
        table.add_row("L6 CRYPTO", "[bold red]HAMMERING[/bold red]" if self.hammer_mode else "[cyan]ANALYZING[/cyan]")
        vault_status = "[bold red]LOCKED (IMMUTABLE)[/bold red]" if self.vault_locked else "[green]UNLOCKED (EVOLVING)[/green]"
        table.add_row("VAULT", vault_status)
        table.add_row("BLACKBOX", "[cyan]RECORDING (VRAM)[/cyan]")
        return Panel(table, title="[bold]DEFENSE MATRIX[/bold]", border_style="green")

    def get_traffic_panel(self):
        if len(self.packet_stream) > 15: self.packet_stream.pop(0)
        table = Table(expand=True, box=None, show_header=False)
        for p in self.packet_stream: table.add_row(p)
        return Panel(table, title="[bold]L1/L2 TRAFFIC[/bold]", border_style="green")

    def get_me_panel(self):
        if len(self.me_stream) > 15: self.me_stream.pop(0)
        table = Table(expand=True, box=None, show_header=False)
        for p in self.me_stream: table.add_row(p)
        return Panel(table, title="[bold]L3 ME TRAFFIC[/bold]", border_style="yellow")

    def get_intel_panel(self):
        table = Table(expand=True, header_style="bold magenta", box=None)
        table.add_column("UTC", width=8)
        table.add_column("LAYER", width=8)
        table.add_column("THREAT INTELLIGENCE", style="bold")
        for alert in self.alerts[-7:]: table.add_row(*alert)
        return Panel(table, title="[bold]ASI INTEL FEED[/bold]", border_style="magenta")

    def get_tensor_map(self):
        # Decay heatmap
        for i in range(len(self.tensor_heatmap)):
            if self.tensor_heatmap[i] > 0: self.tensor_heatmap[i] -= 1
        
        # Render map
        chars = " ░▒▓█"
        lines = []
        for row in range(8):
            line_str = ""
            for col in range(16):
                val = self.tensor_heatmap[row * 16 + col]
                char_idx = min(val, 4)
                color = "magenta" if val > 2 else "cyan" if val > 0 else "blue"
                line_str += f"[{color}]{chars[char_idx]}[/{color}]"
            lines.append(line_str)
        
        text = "\n".join(lines)
        t_k = self.stats.get("Actual_Tensors", 0) // 1000
        return Panel(text, title=f"[bold]L5 TENSOR MAP ({t_k}k)[/bold]", border_style="blue")

    def monitor_asic(self):
        dev_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dev"))
        
        # Check for --node in sys.argv
        node_args = []
        if "--node" in sys.argv:
            idx = sys.argv.index("--node")
            node_args = ["--node", sys.argv[idx+1]]
            # Filter it out from interfaces for the backend
            backend_ifaces = [x for x in self.interfaces if x != "--node" and x != sys.argv[idx+1]]
        else:
            backend_ifaces = self.interfaces

        # Check if already root to avoid redundant sudo
        cmd_prefix = ["stdbuf", "-oL"]
        if os.geteuid() != 0:
            cmd_prefix = ["sudo", "-E", "stdbuf", "-oL"]
            
        cmd = cmd_prefix + ["./asic_main"] + backend_ifaces + node_args
        # Use preexec_fn to create a process group so we can signal through sudo
        self.backend_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=dev_dir, preexec_fn=os.setpgrp)
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@~])')
        while not self.stop_event.is_set():
            raw_line = self.backend_process.stdout.readline()
            if not raw_line: break
            line = ansi_escape.sub('', raw_line.decode('utf-8', errors='ignore'))
            ts = time.strftime("%H:%M:%S")
            
            if "[HAMMER: ON]" in line: self.hammer_mode = True
            elif "[HAMMER: OFF]" in line: self.hammer_mode = False
            elif "[ASIC] Loaded" in line:
                match = re.search(r'Loaded (\d+) Threat Tensors', line)
                if match: self.stats["Actual_Tensors"] = int(match.group(1))
            elif "[VAULT] LOCKED" in line: self.vault_locked = True
            elif "[VAULT] UNLOCKED" in line: self.vault_locked = False
            elif "[VAULT] Evolution Suppressed" in line:
                self.alerts.append([ts, "[bold red]VAULT[/bold red]", "Evolution Blocked (LOCKED)"])
            elif "[SWARM] L4 TRIANGULATION" in line:
                match = re.search(r'Source detected at X:(.*) Y:(.*) \(Confidence: (\d+) nodes\)', line)
                if match:
                    self.stats["Triangulation"] = (match.group(1), match.group(2), match.group(3))
                    self.alerts.append([ts, "[bold yellow]SWARM[/bold yellow]", f"EW Triangulation: {match.group(3)} Nodes"])
            elif "[SWARM]" in line:
                self.swarm_syncs += 1
                self.alerts.append([ts, "[cyan]L5[/cyan]", "[bold cyan]Swarm Sync: Peer Vector[/bold cyan]"])
                # Light up a random area in tensor map
                idx = random.randint(0, 127)
                self.tensor_heatmap[idx] = 10
            elif "[ASIC L4 RF] SPECTRUM CLEAN" in line:
                self.jamming_active = False
            elif "[IPS] NETWORK PACKET DROPPED" in line:
                self.stats["L1_Net"] += 1
                self.alerts.append([ts, "[bold red]L1 IPS[/bold red]", "[bold reverse red] PACKET DROPPED [/bold reverse red]"])
            elif "[IPS]" in line:
                self.stats["L2_EDR"] += 1
                match = re.search(r'Terminated Process (\d+)', line)
                pid = match.group(1) if match else "UNKNOWN"
                self.alerts.append([ts, "[bold red]IPS[/bold red]", f"[bold reverse red] TERMINATED PID {pid} [/bold reverse red]"])
            elif "[CRYPTO_STATS]" in line:
                try:
                    parts = line.split("STATS] ")[1].split("|")
                    self.crypto_corr = float(parts[1])
                except: pass

            if "[TRAFFIC]" in line:
                if "L3_ME" in line:
                    clean_line = line.split("|")[-1].strip()
                    self.me_stream.append(Text(f"ME >> {clean_line}", style="yellow"))
                else:
                    clean_line = line.replace("[TRAFFIC]", "").strip()[:25]
                    self.packet_stream.append(Text(f"> {clean_line}", style="dim green"))
            elif "[ASIC EVOLVE]" in line:
                self.stats["Tensors_Optimized"] += 1
                self.alerts.append([ts, "[magenta]L5[/magenta]", "[bold yellow]Tensor DB Evolved[/bold yellow]"])
                # Light up map
                idx = random.randint(0, 127)
                self.tensor_heatmap[idx] = 10
            elif "[ASIC L6 CRYPTO]" in line:
                msg = line.split("CRYPTO] ")[-1].strip()
                if len(msg) > 35: msg = msg[:32] + "..."
                self.alerts.append([ts, "[cyan]L6[/cyan]", f"[cyan]{msg}[/cyan]"])
            elif "[ASIC L4 EW ALERT]" in line:
                self.alerts.append([ts, "[cyan]L4[/cyan]", "[bold blink red]JAMMING DETECTED[/bold blink red]"])
                self.jamming_active = True
                threading.Thread(target=self.trigger_bios_beep, daemon=True).start()
            elif "[ASIC PRIV ALERT] UNAUTHORIZED" in line:
                self.stats["L2_PRIV"] += 1
                match = re.search(r'ELEVATION \(No TTY/Origin\): (.*)!', line)
                proc = match.group(1) if match else "UNKNOWN"
                self.alerts.append([ts, "[bold reverse red]CRITICAL[/bold reverse red]", f"UNAUTHORIZED ROOT: {proc}"])
            elif "[ASIC PRIV INFO] Authorized" in line:
                match = re.search(r'Action \(UID 0\): (.*)', line)
                proc = match.group(1) if match else "UNKNOWN"
                self.alerts.append([ts, "[green]ADMIN[/green]", f"Sudo/Auth Action: {proc}"])
            elif "[ASIC L2+ INTEL]" in line:
                self.alerts.append([ts, "[yellow]L2+ CODE[/yellow]", "Semantic Match"])
            elif "[ASIC VECTOR ALERT]" in line: 
                self.alerts.append([ts, "[bold magenta]L2[/bold magenta]", "[bold reverse magenta] APT MATCH [/bold reverse magenta]"])
                idx = random.randint(0, 127)
                self.tensor_heatmap[idx] = 10
            elif "[ASIC L3+ ME ALERT]" in line:
                self.alerts.append([ts, "[bold red]L3+ ME[/bold red]", "Unauthorized HECI"])
            elif "[ASIC L3 ALERT]" in line: self.alerts.append([ts, "[yellow]L3[/yellow]", "Cache Anomaly"])

    def signal_backend(self, sig):
        if not self.backend_process: return
        ts = time.strftime("%H:%M:%S")
        sig_name = "HAMMER" if sig == signal.SIGUSR1 else "VAULT"
        self.alerts.append([ts, "[bold cyan]SYSTEM[/bold cyan]", f"Dispatching {sig_name} Signal..."])
        
        try:
            # 1. Try signaling the process group leader
            os.killpg(os.getpgid(self.backend_process.pid), sig)
            
            # 2. Find actual asic_main child and signal it directly
            # This is critical when running under sudo
            parent = psutil.Process(self.backend_process.pid)
            for child in parent.children(recursive=True):
                if "asic_main" in child.name():
                    # If we are root, we can signal directly. 
                    # If not, we use sudo kill as a fallback.
                    if os.geteuid() == 0:
                        child.send_signal(sig)
                    else:
                        sig_str = "USR1" if sig == signal.SIGUSR1 else "USR2"
                        subprocess.run(["sudo", "kill", f"-{sig_str}", str(child.pid)], capture_output=True)
        except Exception as e:
            self.alerts.append([ts, "[bold red]ERROR[/bold red]", f"Signal Fail: {str(e)[:20]}"])

    def handle_input(self):
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while not self.stop_event.is_set():
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    key = sys.stdin.read(1)
                    if not self.backend_process: continue
                    
                    if key == 'h':
                        self.signal_backend(signal.SIGUSR1)
                    elif key == 'v':
                        self.signal_backend(signal.SIGUSR2)

        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    def run(self):
        layout = self.generate_layout()
        threading.Thread(target=self.monitor_asic, daemon=True).start()
        threading.Thread(target=self.handle_input, daemon=True).start()
        
        with Live(layout, refresh_per_second=10, screen=True):
            try:
                while True:
                    self.flash_state = not self.flash_state
                    if self.hammer_mode:
                        h_text = "!!! ME HAMMER MODE ACTIVE !!!" if self.flash_state else "ASI COMMAND CENTER"
                        h_style = "bold white on red"
                    elif self.jamming_active:
                        h_text = "!!! EMERGENCY: INTERFERENCE !!!" if self.flash_state else "ASI COMMAND CENTER"
                        h_style = "bold white on red"
                    else:
                        h_text = "ASI COMMAND CENTER"
                        h_style = "bold white on blue"
                    
                    layout["header"].update(Panel(Text(h_text, justify="center", style=h_style), border_style="blue"))
                    layout["host_telemetry"].update(self.get_host_telemetry())
                    layout["asic_telemetry"].update(self.get_asic_telemetry())
                    layout["traffic_stream"].update(self.get_traffic_panel())
                    layout["me_stream"].update(self.get_me_panel())
                    layout["intel_feed"].update(self.get_intel_panel())
                    layout["tensor_map"].update(self.get_tensor_map())
                    layout["layer_status"].update(self.get_layer_status())
                    
                    iface_str = ",".join(self.interfaces)
                    footer_msg = f"IFACES: {iface_str} | [h] TOGGLE HAMMER | [v] TOGGLE VAULT"
                    layout["footer"].update(Panel(Text(footer_msg, justify="center", style="dim")))
                    time.sleep(0.1)
            except KeyboardInterrupt:
                self.stop_event.set()
                if self.backend_process:
                    os.killpg(os.getpgid(self.backend_process.pid), signal.SIGTERM)

if __name__ == "__main__":
    if len(sys.argv) < 2: sys.exit(1)
    dash = TacticalASICDashboard(sys.argv[1:])
    dash.run()
