#!/usr/bin/env python3
"""
Desktop GUI for Network Packet Capture Tool
Provides a graphical interface to run captures, view output, and generate reports.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import subprocess
import threading
import json
import os
from datetime import datetime
from pathlib import Path


class PacketCaptureGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Capture Tool - Desktop GUI")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)

        self.project_dir = Path(__file__).parent
        self.capture_process = None
        self.capture_thread = None
        self.is_capturing = False
        self.output_buffer = []
        self.test_results = []

        self.setup_ui()
        self.check_dependencies()

    def setup_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)

        # Title
        title_label = ttk.Label(main_frame, text="Network Packet Capture Tool", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 10))

        # Left Panel - Controls
        self.setup_control_panel(main_frame)

        # Center Panel - Output
        self.setup_output_panel(main_frame)

        # Right Panel - Test Report
        self.setup_report_panel(main_frame)

        # Bottom Panel - Status
        self.setup_status_bar(main_frame)

    def setup_control_panel(self, parent):
        control_frame = ttk.LabelFrame(parent, text="Capture Controls", padding="10")
        control_frame.grid(row=1, column=0, rowspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        control_frame.columnconfigure(1, weight=1)

        # Interface selection
        ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var, width=30)
        self.interface_combo.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=2)
        ttk.Button(control_frame, text="Refresh", command=self.refresh_interfaces, width=10).grid(row=0, column=2, padx=2)

        # Packet count
        ttk.Label(control_frame, text="Packet Count:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.count_var = tk.StringVar(value="0")
        ttk.Entry(control_frame, textvariable=self.count_var, width=10).grid(row=1, column=1, sticky=tk.W, pady=2)
        ttk.Label(control_frame, text="(0 = unlimited)").grid(row=1, column=2, sticky=tk.W)

        # BPF Filter
        ttk.Label(control_frame, text="BPF Filter:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.filter_var = tk.StringVar()
        self.filter_combo = ttk.Combobox(control_frame, textvariable=self.filter_var, width=30)
        self.filter_combo['values'] = [
            "", "tcp port 80", "tcp port 443", "udp port 53", "icmp", "arp",
            "host 192.168.1.1", "net 192.168.1.0/24", "tcp port 22", "tcp port 21"
        ]
        self.filter_combo.grid(row=2, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=2)

        # Output file
        ttk.Label(control_frame, text="Output PCAP:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.output_var = tk.StringVar()
        ttk.Entry(control_frame, textvariable=self.output_var, width=25).grid(row=3, column=1, sticky=(tk.W, tk.E), pady=2)
        ttk.Button(control_frame, text="Browse", command=self.browse_output, width=10).grid(row=3, column=2, padx=2)

        # Options
        self.verbose_var = tk.BooleanVar()
        ttk.Checkbutton(control_frame, text="Verbose (show MAC)", variable=self.verbose_var).grid(row=4, column=0, columnspan=3, sticky=tk.W, pady=5)

        # Action Buttons
        btn_frame = ttk.Frame(control_frame)
        btn_frame.grid(row=5, column=0, columnspan=3, pady=10, sticky=(tk.W, tk.E))
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)
        btn_frame.columnconfigure(2, weight=1)

        self.start_btn = ttk.Button(btn_frame, text="START CAPTURE", command=self.start_capture, style="Accent.TButton")
        self.start_btn.grid(row=0, column=0, padx=2, sticky=(tk.W, tk.E))

        self.stop_btn = ttk.Button(btn_frame, text="STOP", command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=1, padx=2, sticky=(tk.W, tk.E))

        ttk.Button(btn_frame, text="CLEAR OUTPUT", command=self.clear_output).grid(row=0, column=2, padx=2, sticky=(tk.W, tk.E))

        # Quick Test Buttons
        test_frame = ttk.LabelFrame(control_frame, text="Quick Tests", padding="5")
        test_frame.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        test_frame.columnconfigure(0, weight=1)
        test_frame.columnconfigure(1, weight=1)

        tests = [
            ("HTTP (port 80)", "tcp port 80"),
            ("HTTPS (port 443)", "tcp port 443"),
            ("DNS (port 53)", "udp port 53"),
            ("ICMP/Ping", "icmp"),
            ("ARP", "arp"),
            ("SSH (port 22)", "tcp port 22"),
        ]
        for i, (label, filter_str) in enumerate(tests):
            row = i // 2
            col = i % 2
            ttk.Button(test_frame, text=label, command=lambda f=filter_str: self.run_quick_test(f)).grid(
                row=row, column=col, padx=2, pady=2, sticky=(tk.W, tk.E))

        # Report Buttons
        report_frame = ttk.Frame(control_frame)
        report_frame.grid(row=7, column=0, columnspan=3, pady=10, sticky=(tk.W, tk.E))
        report_frame.columnconfigure(0, weight=1)
        report_frame.columnconfigure(1, weight=1)

        ttk.Button(report_frame, text="GENERATE REPORT", command=self.generate_report).grid(row=0, column=0, padx=2, sticky=(tk.W, tk.E))
        ttk.Button(report_frame, text="EXPORT REPORT", command=self.export_report).grid(row=0, column=1, padx=2, sticky=(tk.W, tk.E))

    def setup_output_panel(self, parent):
        output_frame = ttk.LabelFrame(parent, text="Capture Output", padding="5")
        output_frame.grid(row=1, column=1, rowspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)

        # Output text area
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, font=("Consolas", 9))
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.output_text.config(state=tk.DISABLED)

        # Tag configurations for colored output
        self.output_text.tag_config("timestamp", foreground="#888888")
        self.output_text.tag_config("packet_header", foreground="#00AA00", font=("Consolas", 9, "bold"))
        self.output_text.tag_config("protocol_tcp", foreground="#0066CC")
        self.output_text.tag_config("protocol_udp", foreground="#CC6600")
        self.output_text.tag_config("protocol_icmp", foreground="#AA00AA")
        self.output_text.tag_config("protocol_arp", foreground="#CC0000")
        self.output_text.tag_config("protocol_dns", foreground="#008888")
        self.output_text.tag_config("payload", foreground="#666666", font=("Consolas", 8))
        self.output_text.tag_config("summary", foreground="#333333", font=("Consolas", 9, "bold"))
        self.output_text.tag_config("error", foreground="#FF0000", font=("Consolas", 9, "bold"))
        self.output_text.tag_config("info", foreground="#0000AA")

    def setup_report_panel(self, parent):
        report_frame = ttk.LabelFrame(parent, text="Test Report", padding="5")
        report_frame.grid(row=1, column=2, rowspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(10, 0))
        report_frame.columnconfigure(0, weight=1)
        report_frame.rowconfigure(0, weight=1)

        # Report treeview
        columns = ("Test", "Status", "Packets", "Protocols", "Duration", "Time")
        self.report_tree = ttk.Treeview(report_frame, columns=columns, show="headings", height=20)
        for col in columns:
            self.report_tree.heading(col, text=col)
            self.report_tree.column(col, width=100, anchor=tk.CENTER)
        self.report_tree.column("Test", width=180, anchor=tk.W)
        self.report_tree.column("Protocols", width=150, anchor=tk.W)
        self.report_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Scrollbar for treeview
        tree_scroll = ttk.Scrollbar(report_frame, orient=tk.VERTICAL, command=self.report_tree.yview)
        tree_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.report_tree.configure(yscrollcommand=tree_scroll.set)

        # Report details
        detail_frame = ttk.LabelFrame(report_frame, text="Test Details", padding="5")
        detail_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        detail_frame.columnconfigure(0, weight=1)

        self.detail_text = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD, height=8, font=("Consolas", 9))
        self.detail_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
        self.detail_text.config(state=tk.DISABLED)

        self.report_tree.bind("<<TreeviewSelect>>", self.on_report_select)

    def setup_status_bar(self, parent):
        status_frame = ttk.Frame(parent)
        status_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        status_frame.columnconfigure(1, weight=1)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, text="Status:").grid(row=0, column=0, padx=(0, 5))
        ttk.Label(status_frame, textvariable=self.status_var).grid(row=0, column=1, sticky=tk.W)

        self.packet_count_var = tk.StringVar(value="Packets: 0")
        ttk.Label(status_frame, textvariable=self.packet_count_var).grid(row=0, column=2, padx=20)

        self.progress = ttk.Progressbar(status_frame, mode='indeterminate')
        self.progress.grid(row=0, column=3, padx=10, sticky=(tk.W, tk.E))

    def check_dependencies(self):
        self.log_output("Checking dependencies...", "info")
        try:
            import scapy
            self.log_output(f"Scapy {scapy.__version__} found", "info")
        except ImportError:
            self.log_output("ERROR: Scapy not installed. Run: pip install scapy", "error")
            messagebox.showerror("Missing Dependency", "Scapy is not installed.\nRun: pip install scapy")

        self.refresh_interfaces()

    def refresh_interfaces(self):
        self.log_output("Refreshing interfaces...", "info")
        try:
            result = subprocess.run(
                ["python", "packet_capture.py", "--list-interfaces"],
                capture_output=True, text=True, cwd=self.project_dir, timeout=10
            )
            interfaces = []
            for line in result.stdout.split('\n'):
                if ' - ' in line and not line.startswith('Available'):
                    iface_name = line.split(' - ')[0].strip()
                    interfaces.append(iface_name)
            self.interface_combo['values'] = interfaces
            if interfaces:
                self.interface_combo.current(0)
            self.log_output(f"Found {len(interfaces)} interfaces", "info")
        except Exception as e:
            self.log_output(f"Error refreshing interfaces: {e}", "error")

    def browse_output(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
            initialdir=self.project_dir
        )
        if filename:
            self.output_var.set(filename)

    def log_output(self, message, tag="info"):
        self.output_text.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.output_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
        self.output_text.insert(tk.END, f"{message}\n", tag)
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.output_buffer.append(f"[{timestamp}] {message}")

    def clear_output(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.output_buffer = []

    def start_capture(self):
        if self.is_capturing:
            return

        interface = self.interface_var.get()
        count = self.count_var.get()
        filter_str = self.filter_var.get()
        output_file = self.output_var.get()
        verbose = self.verbose_var.get()

        if not interface:
            messagebox.showwarning("Warning", "Please select a network interface")
            return

        try:
            count = int(count)
        except ValueError:
            messagebox.showerror("Error", "Packet count must be a number")
            return

        self.is_capturing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start()
        self.status_var.set("Capturing...")
        self.packet_count_var.set("Packets: 0")

        self.log_output(f"Starting capture on {interface}...", "info")
        if filter_str:
            self.log_output(f"Filter: {filter_str}", "info")
        if output_file:
            self.log_output(f"Output: {output_file}", "info")

        self.capture_thread = threading.Thread(target=self.run_capture, args=(interface, count, filter_str, output_file, verbose))
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def run_capture(self, interface, count, filter_str, output_file, verbose):
        try:
            cmd = ["python", "packet_capture.py", "-i", interface]
            if count > 0:
                cmd.extend(["-c", str(count)])
            if filter_str:
                cmd.extend(["-f", filter_str])
            if output_file:
                cmd.extend(["-o", output_file])
            if verbose:
                cmd.append("-v")

            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                cwd=self.project_dir
            )

            packet_count = 0
            protocols = set()
            start_time = datetime.now()

            for line in iter(self.capture_process.stdout.readline, ''):
                if not self.is_capturing:
                    break
                line = line.rstrip()
                if line:
                    self.root.after(0, lambda l=line: self.process_output_line(l))
                    if "TCP" in line or "UDP" in line or "ICMP" in line or "ARP" in line or "DNS" in line:
                        packet_count += 1
                        self.root.after(0, lambda c=packet_count: self.packet_count_var.set(f"Packets: {c}"))
                        for proto in ["TCP", "UDP", "ICMP", "ARP", "DNS"]:
                            if proto in line:
                                protocols.add(proto)

            self.capture_process.wait()
            duration = (datetime.now() - start_time).total_seconds()

            self.root.after(0, lambda: self.capture_finished(packet_count, protocols, duration, filter_str or "none", output_file or "none"))

        except Exception as e:
            self.root.after(0, lambda: self.capture_error(str(e)))

    def process_output_line(self, line):
        self.output_text.config(state=tk.NORMAL)
        tag = "info"
        if line.startswith('[') and '] ' in line:
            tag = "packet_header"
            if "TCP" in line:
                tag = "protocol_tcp"
            elif "UDP" in line:
                tag = "protocol_udp"
            elif "ICMP" in line:
                tag = "protocol_icmp"
            elif "ARP" in line:
                tag = "protocol_arp"
            elif "DNS" in line:
                tag = "protocol_dns"
        elif "Payload" in line:
            tag = "payload"
        elif "SUMMARY" in line or "Protocol" in line or "Total" in line:
            tag = "summary"
        elif "Error" in line or "ERROR" in line:
            tag = "error"

        self.output_text.insert(tk.END, line + "\n", tag)
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.output_buffer.append(line)

    def capture_finished(self, packet_count, protocols, duration, filter_used, output_file):
        self.is_capturing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()
        self.status_var.set("Capture completed")
        self.packet_count_var.set(f"Packets: {packet_count}")

        self.log_output(f"Capture finished. Packets: {packet_count}, Duration: {duration:.1f}s", "summary")

        # Add to test report
        test_name = f"Capture_{datetime.now().strftime('%H%M%S')}"
        if filter_used != "none":
            test_name += f"_{filter_used.replace(' ', '_').replace('port', 'p')}"
        status = "PASS" if packet_count > 0 else "NO DATA"
        protocols_str = ", ".join(sorted(protocols)) if protocols else "None"

        self.test_results.append({
            "test": test_name,
            "status": status,
            "packets": packet_count,
            "protocols": protocols_str,
            "duration": f"{duration:.1f}s",
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "filter": filter_used,
            "output": output_file,
            "details": "\n".join(self.output_buffer[-50:])
        })
        self.update_report_tree()

        # Auto-generate report
        self.auto_generate_report()

    def capture_error(self, error):
        self.is_capturing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()
        self.status_var.set("Error")
        self.log_output(f"Capture error: {error}", "error")
        messagebox.showerror("Capture Error", error)

    def stop_capture(self):
        if self.is_capturing and self.capture_process:
            self.capture_process.terminate()
            self.log_output("Stopping capture...", "info")

    def run_quick_test(self, filter_str):
        self.filter_var.set(filter_str)
        self.count_var.set("20")
        self.output_var.set("")
        self.start_capture()

    def update_report_tree(self):
        for item in self.report_tree.get_children():
            self.report_tree.delete(item)
        for result in self.test_results:
            self.report_tree.insert("", tk.END, values=(
                result["test"], result["status"], result["packets"],
                result["protocols"], result["duration"], result["time"]
            ), tags=(result["status"],))

        self.report_tree.tag_configure("PASS", foreground="green")
        self.report_tree.tag_configure("NO DATA", foreground="orange")
        self.report_tree.tag_configure("FAIL", foreground="red")

    def on_report_select(self, event):
        selection = self.report_tree.selection()
        if selection:
            item = self.report_tree.item(selection[0])
            test_name = item['values'][0]
            for result in self.test_results:
                if result["test"] == test_name:
                    self.show_test_details(result)
                    break

    def show_test_details(self, result):
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete(1.0, tk.END)
        details = f"""Test: {result['test']}
Status: {result['status']}
Time: {result['time']}
Duration: {result['duration']}
Packets Captured: {result['packets']}
Protocols: {result['protocols']}
Filter: {result['filter']}
Output File: {result['output']}

--- Last 50 Output Lines ---
{result['details']}
"""
        self.detail_text.insert(tk.END, details)
        self.detail_text.config(state=tk.DISABLED)

    def auto_generate_report(self):
        """Automatically generate report after each capture"""
        if not self.test_results:
            return

        self.log_output("Auto-generating test report...", "info")

        report = {
            "generated": datetime.now().isoformat(),
            "tool": "Network Packet Capture Tool",
            "total_tests": len(self.test_results),
            "tests": self.test_results
        }

        # Show summary in output
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, "\n" + "="*60 + "\n", "summary")
        self.output_text.insert(tk.END, "AUTO TEST REPORT SUMMARY\n", "summary")
        self.output_text.insert(tk.END, "="*60 + "\n", "summary")
        self.output_text.insert(tk.END, f"Generated: {report['generated']}\n", "info")
        self.output_text.insert(tk.END, f"Total Tests: {report['total_tests']}\n\n", "info")

        for i, test in enumerate(self.test_results, 1):
            self.output_text.insert(tk.END, f"Test {i}: {test['test']}\n", "summary")
            self.output_text.insert(tk.END, f"  Status: {test['status']}\n", "info")
            self.output_text.insert(tk.END, f"  Packets: {test['packets']}\n", "info")
            self.output_text.insert(tk.END, f"  Protocols: {test['protocols']}\n", "info")
            self.output_text.insert(tk.END, f"  Duration: {test['duration']}\n", "info")
            self.output_text.insert(tk.END, f"  Filter: {test['filter']}\n", "info")
            self.output_text.insert(tk.END, f"  Output: {test['output']}\n\n", "info")

        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)

    def generate_report(self):
        if not self.test_results:
            messagebox.showinfo("No Data", "No test results to report. Run some captures first.")
            return

        self.log_output("Generating full test report...", "info")

        report = {
            "generated": datetime.now().isoformat(),
            "tool": "Network Packet Capture Tool",
            "total_tests": len(self.test_results),
            "tests": self.test_results
        }

        # Show summary in output
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, "\n" + "="*60 + "\n", "summary")
        self.output_text.insert(tk.END, "TEST REPORT SUMMARY\n", "summary")
        self.output_text.insert(tk.END, "="*60 + "\n", "summary")
        self.output_text.insert(tk.END, f"Generated: {report['generated']}\n", "info")
        self.output_text.insert(tk.END, f"Total Tests: {report['total_tests']}\n\n", "info")

        for i, test in enumerate(self.test_results, 1):
            self.output_text.insert(tk.END, f"Test {i}: {test['test']}\n", "summary")
            self.output_text.insert(tk.END, f"  Status: {test['status']}\n", "info")
            self.output_text.insert(tk.END, f"  Packets: {test['packets']}\n", "info")
            self.output_text.insert(tk.END, f"  Protocols: {test['protocols']}\n", "info")
            self.output_text.insert(tk.END, f"  Duration: {test['duration']}\n", "info")
            self.output_text.insert(tk.END, f"  Filter: {test['filter']}\n", "info")
            self.output_text.insert(tk.END, f"  Output: {test['output']}\n\n", "info")

        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)

        messagebox.showinfo("Report Generated", "Test report generated and displayed in output panel.")

    def export_report(self):
        if not self.test_results:
            messagebox.showinfo("No Data", "No test results to export.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Report", "*.json"), ("Text Report", "*.txt"), ("All files", "*.*")],
            initialdir=self.project_dir,
            initialfile=f"packet_capture_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        if not filename:
            return

        try:
            if filename.endswith('.json'):
                report = {
                    "generated": datetime.now().isoformat(),
                    "tool": "Network Packet Capture Tool",
                    "total_tests": len(self.test_results),
                    "tests": self.test_results
                }
                with open(filename, 'w') as f:
                    json.dump(report, f, indent=2)
            else:
                with open(filename, 'w') as f:
                    f.write(f"Network Packet Capture Tool - Test Report\n")
                    f.write(f"Generated: {datetime.now().isoformat()}\n")
                    f.write(f"Total Tests: {len(self.test_results)}\n")
                    f.write("="*60 + "\n\n")
                    for i, test in enumerate(self.test_results, 1):
                        f.write(f"Test {i}: {test['test']}\n")
                        f.write(f"  Status: {test['status']}\n")
                        f.write(f"  Packets: {test['packets']}\n")
                        f.write(f"  Protocols: {test['protocols']}\n")
                        f.write(f"  Duration: {test['duration']}\n")
                        f.write(f"  Filter: {test['filter']}\n")
                        f.write(f"  Output: {test['output']}\n")
                        f.write(f"  Time: {test['time']}\n\n")

            self.log_output(f"Report exported to {filename}", "summary")
            messagebox.showinfo("Success", f"Report exported to:\n{filename}")
        except Exception as e:
            self.log_output(f"Export error: {e}", "error")
            messagebox.showerror("Export Error", str(e))


def main():
    root = tk.Tk()

    # Configure style
    style = ttk.Style()
    style.theme_use('clam')

    # Custom button style
    style.configure("Accent.TButton", font=("Arial", 10, "bold"))

    app = PacketCaptureGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()