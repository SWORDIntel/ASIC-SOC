
import os
import sys
import time
import subprocess
import threading
import random
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn
from rich.columns import Columns

console = Console()

class ProfessionalASICDashboard:
    def __init__(self, interface):
        self.interface = interface
        self.alerts = []
        self.stats = {
            "L1_Net": 0, "L2_EDR": 0, "L2_PRIV": 0, 
            "L3_HW": 0, "L4_RF": 0, "ASI_Load": 0
        }
        self.jamming_active = False
        self.stop_event = threading.Event()
        self.flash_state = False
        self.window_title = "SECURITY_ASIC_COMMAND_CENTER"
        sys.stdout.write(f"\x1b]2;{self.window_title}\x07")

    def force_foreground(self):
        try:
            subprocess.run(["wmctrl", "-a", self.window_title], capture_output=True)
            subprocess.run(["wmctrl", "-R", self.window_title], capture_output=True)
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
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        layout["main"].split_row(
            Layout(name="left", size=35),
            Layout(name="center"),
            Layout(name="right", size=35)
        )
        return layout

    def get_asic_metrics(self):
        table = Table(show_header=False, expand=True, box=None)
        # Randomize ASI Load for visual telemetry effect
        load = random.randint(12, 18) if not self.jamming_active else random.randint(85, 99)
        table.add_row("CORE ARCH", "[bold cyan]FERMI-QIHSE v2.5[/bold cyan]")
        table.add_row("ASI LOAD", f"[bold {'red' if load > 80 else 'green'}]{load}%[/bold {'red' if load > 80 else 'green'}]")
        table.add_row("VRAM REG", "[bold yellow]114/1219 MiB[/bold yellow]")
        table.add_row("THROUGHPUT", "[bold white]1.82 GB/s[/bold white]")
        table.add_row("TEMP", "[bold green]32°C[/bold green]")
        return table

    def get_layer_status(self):
        table = Table(show_header=False, expand=True, box=None)
        table.add_row("L1 EDGE", "[green]SECURE[/green]")
        table.add_row("L2 EDR", "[green]ACTIVE[/green]")
        table.add_row("L2 PRIV", "[green]ENFORCED[/green]")
        table.add_row("L3 HW", "[green]NOMINAL[/green]")
        table.add_row("L4 RF", "[red]ALERT[/red]" if self.jamming_active else "[green]PASSIVE[/green]")
        table.add_row("ME SENTRY", "[green]LOCKED[/green]")
        return table

    def get_alerts_log(self):
        table = Table(expand=True, header_style="bold blue", box=None)
        table.add_column("UTC", style="dim", width=8)
        table.add_column("VECTOR", width=10)
        table.add_column("THREAT INTELLIGENCE", style="bold")
        
        for alert in self.alerts[-15:]:
            table.add_row(*alert)
        return table

    def monitor_asic(self):
        dev_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dev"))
        cmd = ["sudo", "stdbuf", "-oL", "./asic_main", self.interface]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=dev_dir)
        
        while not self.stop_event.is_set():
            line = process.stdout.readline()
            if not line: break
            ts = time.strftime("%H:%M:%S")
            if "[ASIC L4 EW ALERT]" in line:
                self.stats["L4_RF"] += 1
                self.alerts.append([ts, "[cyan]RF/EW[/cyan]", "[bold blink red]C-BAND SPECTRUM SATURATION[/bold blink red]"])
                if not self.jamming_active:
                    self.jamming_active = True
                    threading.Thread(target=self.trigger_bios_beep, daemon=True).start()
            elif "[ASIC PRIV ALERT]" in line:
                self.stats["L2_PRIV"] += 1
                self.alerts.append([ts, "[red]PRIV[/red]", "Unauthorized UID 0 Transition"])
            elif "[ASIC VECTOR ALERT]" in line:
                self.stats["L2_EDR"] += 1
                self.alerts.append([ts, "[magenta]EDR[/magenta]", "APT Pattern Behavioral Match"])
            elif "[ASIC L3 ALERT]" in line:
                self.stats["L3_HW"] += 1
                self.alerts.append([ts, "[yellow]HW[/yellow]", "Cache-Timing Anomaly Detected"])

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
                    
                    layout["header"].update(Panel(Text("ASI COMMAND: GLOBAL THREAT CONTEXT", justify="center", style=h_style), border_style="blue"))
                    layout["left"].update(Panel(self.get_asic_metrics(), title="[bold]ASIC HARDWARE[/bold]", border_style="cyan"))
                    layout["center"].update(Panel(self.get_alerts_log(), title="[bold]INTELLIGENCE FEED[/bold]", border_style="magenta"))
                    layout["right"].update(Panel(self.get_layer_status(), title="[bold]LAYER DEFENSE[/bold]", border_style="green"))
                    
                    footer_text = "!!! EMERGENCY: SPECTRUM INTERFERENCE !!!" if self.jamming_active else f"IFACE: {self.interface} | MODE: HEADLESS ASIC | TRUST: ZERO"
                    layout["footer"].update(Panel(Text(footer_text, justify="center", style="bold red" if self.jamming_active else "dim")))
                    
                    time.sleep(0.1)
            except KeyboardInterrupt:
                self.stop_event.set()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    dash = ProfessionalASICDashboard(sys.argv[1])
    dash.run()
