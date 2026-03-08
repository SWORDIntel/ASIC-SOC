
import os
import sys
import time
import subprocess
import threading
import random
import psutil
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn, TaskProgressColumn
from rich.columns import Columns

console = Console()

class TacticalASICDashboard:
    def __init__(self, interfaces):
        self.interfaces = interfaces
        self.alerts = []
        self.packet_stream = []
        self.stats = {
            "L1_Net": 0, "L2_EDR": 0, "L2_PRIV": 0, 
            "L3_HW": 0, "L4_RF": 0, "ASI_Load": 15
        }
        self.cpu_history = []
        self.jamming_active = False
        self.stop_event = threading.Event()
        self.flash_state = False
        self.window_title = "ASI_TACTICAL_COMMAND_CENTER"
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
            Layout(name="traffic_stream", size=45),
            Layout(name="intel_feed"),
            Layout(name="layer_status", size=25)
        )
        return layout

    def get_host_telemetry(self):
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        table = Table(show_header=False, expand=True, box=None)
        cpu_bar = "|" * int(cpu / 5)
        ram_bar = "|" * int(ram / 5)
        table.add_row("HOST CPU", f"[bold {'red' if cpu > 80 else 'green'}]{cpu}%[/bold {'red' if cpu > 80 else 'green'}]", f"[green]{cpu_bar:<20}[/green]")
        table.add_row("HOST RAM", f"[bold {'red' if ram > 80 else 'blue'}]{ram}%[/bold {'red' if ram > 80 else 'blue'}]", f"[blue]{ram_bar:<20}[/blue]")
        table.add_row("OS KERNEL", "[white]Linux 6.12.73-AMD64[/white]", "[green]STABLE[/green]")
        return Panel(table, title="[bold]SYSTEM VITALS[/bold]", border_style="blue")

    def get_asic_telemetry(self):
        load = self.stats["ASI_Load"] + random.randint(-2, 2)
        table = Table(show_header=False, expand=True, box=None)
        table.add_row("ASIC CORE", "[bold cyan]FERMI-QIHSE v2.5[/bold cyan]", "[cyan]ONLINE[/cyan]")
        table.add_row("COMPUTE LOAD", f"[bold green]{load}%[/bold green]", "[green]RESERVE CAPACITY HIGH[/green]")
        table.add_row("TENSOR DB", "[bold yellow]8,000 VECTORS[/bold yellow]", "[yellow]HIGH FIDELITY[/yellow]")
        table.add_row("GPU TEMP", "[bold green]32°C[/bold green]", "[white]STABLE[/white]")
        return Panel(table, title="[bold]ASIC CO-PROCESSOR[/bold]", border_style="cyan")

    def get_layer_status(self):
        table = Table(show_header=False, expand=True, box=None)
        table.add_row("L1 EDGE", "[green]SECURE[/green]")
        table.add_row("L2 EDR", "[green]ACTIVE[/green]")
        table.add_row("L2 PRIV", "[green]ENFORCED[/green]")
        table.add_row("L2 CODE", "[cyan]OFFLOADING[/cyan]")
        table.add_row("L3 HW", "[green]NOMINAL[/green]")
        table.add_row("L4 RF", "[red]ALERT[/red]" if self.jamming_active else "[green]PASSIVE[/green]")
        table.add_row("L5 EVOLVE", "[magenta]CONTINUOUS[/magenta]" if self.stats.get("Tensors_Optimized", 0) > 0 else "[dim]STANDBY[/dim]")
        table.add_row("L6 CRYPTO", "[cyan]ANALYZING[/cyan]")
        return Panel(table, title="[bold]DEFENSE[/bold]", border_style="green")

    def get_traffic_panel(self):
        if len(self.packet_stream) > 15: self.packet_stream.pop(0)
        table = Table(expand=True, box=None, show_header=False)
        for p in self.packet_stream:
            table.add_row(p)
        return Panel(table, title="[bold]L1 TRAFFIC STREAM[/bold]", border_style="green")

    def get_intel_panel(self):
        table = Table(expand=True, header_style="bold magenta", box=None)
        table.add_column("UTC", width=8)
        table.add_column("LAYER", width=8)
        table.add_column("THREAT INTELLIGENCE", style="bold")
        for alert in self.alerts[-10:]:
            table.add_row(*alert)
        return Panel(table, title="[bold]ASI INTEL FEED[/bold]", border_style="magenta")

    def monitor_asic(self):
        dev_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dev"))
        cmd = ["sudo", "stdbuf", "-oL", "./asic_main"] + self.interfaces
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=dev_dir)
        while not self.stop_event.is_set():
            line = process.stdout.readline()
            if not line: break
            ts = time.strftime("%H:%M:%S")
            # Stylize only explicit [TRAFFIC] lines for the stream
            if "[TRAFFIC]" in line:
                clean_line = line.replace("[TRAFFIC]", "").strip()[:40]
                self.packet_stream.append(Text(f"> {clean_line}", style="dim green"))
            elif "[ASIC L4 EW ALERT]" in line:
                self.alerts.append([ts, "[cyan]L4[/cyan]", "[bold blink red]JAMMING DETECTED[/bold blink red]"])
                self.jamming_active = True
                threading.Thread(target=self.trigger_bios_beep, daemon=True).start()
            elif "[ASIC PRIV ALERT]" in line:
                self.alerts.append([ts, "[red]L2[/red]", "PrivEsc Detected"])
            elif "[ASIC VECTOR ALERT]" in line:
                self.alerts.append([ts, "[magenta]L2[/magenta]", "APT Pattern Match"])
            elif "[ASIC L3 ALERT]" in line:
                self.alerts.append([ts, "[yellow]L3[/yellow]", "Cache Anomaly"])

    def run(self):
        layout = self.generate_layout()
        monitor_thread = threading.Thread(target=self.monitor_asic)
        monitor_thread.daemon = True
        monitor_thread.start()
        with Live(layout, refresh_per_second=10, screen=True):
            try:
                while True:
                    self.flash_state = not self.flash_state
                    h_style = "bold white on red" if (self.jamming_active and self.flash_state) else "bold white on blue"
                    layout["header"].update(Panel(Text("ASI TACTICAL COMMAND: ZERO-TRUST", justify="center", style=h_style), border_style="blue"))
                    layout["host_telemetry"].update(self.get_host_telemetry())
                    layout["asic_telemetry"].update(self.get_asic_telemetry())
                    layout["traffic_stream"].update(self.get_traffic_panel())
                    layout["intel_feed"].update(self.get_intel_panel())
                    layout["layer_status"].update(self.get_layer_status())
                    iface_str = ",".join(self.interfaces)
                    footer_text = "!!! EMERGENCY: INTERFERENCE !!!" if self.jamming_active else f"IFACES: {iface_str} | ASIC NOMINAL (85% SPARE)"
                    layout["footer"].update(Panel(Text(footer_text, justify="center", style="bold red" if self.jamming_active else "dim")))
                    time.sleep(0.1)
            except KeyboardInterrupt:
                self.stop_event.set()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    dash = TacticalASICDashboard(sys.argv[1:])
    dash.run()
