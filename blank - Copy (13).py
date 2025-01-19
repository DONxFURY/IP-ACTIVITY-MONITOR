import psutil
import tkinter as tk
from tkinter import messagebox
import threading
import time
from queue import Queue
import winsound
from random import choice


class IPMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Activity Monitor")
        self.root.geometry("700x450")  # Adjusted to accommodate larger components
        self.root.config(bg="#121212")  # Sleek dark background

        # Customize fonts and colors
        self.bg_colors = ["#232323", "#3A3A3A", "#444444", "#555555"]
        self.button_colors = ["#FF5722", "#673AB7", "#4CAF50", "#FFC107"]
        self.text_colors = ["#FFFFFF", "#FF4081", "#8BC34A", "#03A9F4"]

        # Title and buttons
        self.label = tk.Label(root, text="IP Activity Monitoring", font=("Arial", 16, "bold"), fg="#FFEB3B", bg="#232323")
        self.label.pack(pady=10)

        self.monitor_button = tk.Button(root, text="Start Monitoring", command=self.start_monitoring, font=("Arial", 12), bg=choice(self.button_colors), fg="white")
        self.monitor_button.pack(pady=20)

        self.stop_button = tk.Button(root, text="Stop Monitoring", command=self.stop_monitoring, font=("Arial", 12), bg=choice(self.button_colors), fg="white", state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        self.textbox = tk.Text(root, height=16, width=85, state=tk.DISABLED, wrap=tk.WORD, bg="#121212", fg=choice(self.text_colors), font=("Arial", 10))
        self.textbox.pack(pady=10)

        self.status_label = tk.Label(root, text="Waiting to start monitoring...", font=("Arial", 12), bg="#232323", fg="#8BC34A")
        self.status_label.pack(pady=5)

        # Queue for safe thread communication
        self.ip_queue = Queue()
        self.monitoring_thread = None
        self.monitoring = False
        self.suspicious_ips = ["192.168.0.100", "203.0.113.45"]
        self.exclude_ports = [22, 80]

        # Add a smooth animation for monitoring
        self.animate_label()

    def update_output(self, text):
        """Safely updates the output window in the GUI from another thread."""
        self.textbox.config(state=tk.NORMAL)
        self.textbox.insert(tk.END, text + "\n")
        self.textbox.config(state=tk.DISABLED)
        self.textbox.yview(tk.END)

    def start_monitoring(self):
        """Starts the monitoring in a separate thread."""
        self.monitoring = True
        self.monitor_button.config(state=tk.DISABLED, bg=choice(self.button_colors))
        self.stop_button.config(state=tk.NORMAL, bg=choice(self.button_colors))
        self.status_label.config(text="Monitoring started... Press Stop to stop.")
        self.monitoring_thread = threading.Thread(target=self.monitor_ip_activity, daemon=True)
        self.monitoring_thread.start()
        self.process_output()

    def stop_monitoring(self):
        """Stops the monitoring process."""
        self.monitoring = False
        self.monitor_button.config(state=tk.NORMAL, bg=choice(self.button_colors))
        self.stop_button.config(state=tk.DISABLED, bg=choice(self.button_colors))
        self.status_label.config(text="Monitoring stopped. Press Start to begin again.")

    def monitor_ip_activity(self):
        """Checks current network connections using psutil."""
        while self.monitoring:
            try:
                connections = psutil.net_connections(kind='inet')  # Checking for internet connections
                for conn in connections:
                    ip_src = conn.raddr.ip if conn.raddr else None
                    if ip_src and conn.laddr.port not in self.exclude_ports:  # Filter by port
                        ip_dst = conn.laddr.ip  # Local address
                        remote_port = conn.raddr.port if conn.raddr else "N/A"
                        status = conn.status  # Connection status
                        info = f"Local IP: {ip_dst}, Remote IP: {ip_src}:{remote_port}, Status: {status}"
                        self.ip_queue.put(info)

                        if ip_src in self.suspicious_ips:
                            alert_message = f"ALERT: Suspicious activity detected from IP: {ip_src}:{remote_port}"
                            self.ip_queue.put(f"[ALERT] {alert_message}")
                            self.show_alert(alert_message)
                time.sleep(5)  # Monitor every 5 seconds
            except Exception as e:
                self.ip_queue.put(f"Error during monitoring: {str(e)}")

    def process_output(self):
        """Process all output from the monitoring thread using thread-safe queue."""
        try:
            while True:
                message = self.ip_queue.get_nowait()
                self.update_output(message)
        except Exception as e:
            pass  # No output to process
        finally:
            if self.monitoring:
                self.root.after(100, self.process_output)

    def show_alert(self, message):
        """Show a pop-up with a cool alert and color animations."""
        # Play a sound for alert (Windows specific)
        self.play_sound()

        # Change window color to red for the alert effect
        original_color = self.root.cget("background")
        self.root.configure(background="#FF3333")
        self.root.after(200, lambda: self.root.configure(background=original_color))

        # Custom pop-up with animations
        self.create_custom_popup(message)

    def create_custom_popup(self, message):
        """Creates a custom alert pop-up with animations."""
        alert_popup = tk.Toplevel(self.root)
        alert_popup.title("Suspicious Activity Detected!")
        alert_popup.geometry("400x220")
        alert_popup.config(bg="#D40000")
        
        label = tk.Label(alert_popup, text=message, font=("Arial", 14), fg="white", bg="#D40000", padx=20, pady=20)
        label.pack(fill=tk.BOTH, expand=True)
        
        button = tk.Button(alert_popup, text="Acknowledge", command=alert_popup.destroy, font=("Arial", 12), bg="#4E4EFF", fg="white")
        button.pack(pady=10)

        # Popup animation with fade-in effect
        alert_popup.attributes("-alpha", 0)  # Make it initially invisible
        alert_popup.after(0, lambda: self.fade_in(alert_popup))

    def fade_in(self, popup):
        """Fade-in effect for the alert window."""
        alpha = popup.attributes("-alpha")
        if alpha < 1.0:
            popup.attributes("-alpha", alpha + 0.1)
            self.root.after(50, lambda: self.fade_in(popup))

    def play_sound(self):
        """Plays a sound alert."""
        try:
            winsound.Beep(1000, 500)  # Frequency, duration (in milliseconds)
        except Exception as e:
            print("Sound alert failed:", e)

    def animate_label(self):
        """Animate label to draw attention and make it colorful."""
        colors = ["#FFEB3B", "#FF4081", "#8BC34A", "#03A9F4"]
        def change_color():
            new_color = choice(colors)
            self.label.config(fg=new_color)
            self.root.after(500, change_color)
        
        change_color()  # Initiate the animation

    def update_ip_list(self, ip_list):
        """Update the suspicious IPs list dynamically."""
        self.suspicious_ips = ip_list


# Function to launch the GUI application
def run_gui():
    root = tk.Tk()
    app = IPMonitorApp(root)
    root.mainloop()


# Run the application
if __name__ == "__main__":
    run_gui()
