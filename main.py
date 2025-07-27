import pandas as pd
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import matplotlib.pyplot as plt
import threading
import time

CPU_THRESHOLD = 90
LOGIN_FAILURE_THRESHOLD = 3

window = tk.Tk()
window.title("Cyber Anomaly Detection Tool")
window.geometry("600x400")
window.configure(bg="#1e1e1e")
window.resizable(False, False)

style = ttk.Style()
style.theme_use('clam')
style.configure('TButton', font=('Segoe UI', 10), padding=8, background="#333", foreground="#fff")
style.configure('TLabel', font=('Segoe UI', 10), background="#1e1e1e", foreground="#fff")

menubar = tk.Menu(window, bg="#2c2c2c", fg="white")
help_menu = tk.Menu(menubar, tearoff=0)
help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About", "Cyber Anomaly Detection v1.0\nAuthor: You"))
help_menu.add_command(label="Help", command=lambda: messagebox.showinfo("Help", "1. Click buttons to select CSV files.\n2. View alerts & visualizations.\n3. Data saved to output files."))
menubar.add_cascade(label="Menu", menu=help_menu)
window.config(menu=menubar)

loading_label = None
def show_loading(msg):
    global loading_label
    loading_label = tk.Label(window, text=msg, bg="#1e1e1e", fg="lightgray", font=("Segoe UI", 10, "italic"))
    loading_label.pack(pady=5)
    window.update()

def hide_loading():
    if loading_label:
        loading_label.destroy()

def analyze_cpu_usage():
    def task():
        file_path = filedialog.askopenfilename(title="Select CPU Log CSV")
        if not file_path:
            return

        try:
            show_loading("Analyzing CPU logs...")
            time.sleep(1)

            data = pd.read_csv(file_path)
            data['is_anomaly'] = data['cpu_usage'] > CPU_THRESHOLD
            data['alert_level'] = data['cpu_usage'].apply(
                lambda x: "Critical" if x > 95 else ("Warning" if x > 90 else "Normal")
            )
            data.to_csv('cpu_anomaly_output.csv', index=False)

            messagebox.showinfo("Done", f"{data['is_anomaly'].sum()} anomalies saved to cpu_anomaly_output.csv")

            
            plt.figure(figsize=(8, 4))
            for level, color in [("Normal", "green"), ("Warning", "orange"), ("Critical", "red")]:
                subset = data[data['alert_level'] == level]
                plt.plot(subset['timestamp'], subset['cpu_usage'], 'o-', label=level, color=color)
            plt.axhline(CPU_THRESHOLD, color='gray', linestyle='--', label='Threshold (90%)')
            plt.xticks(rotation=45)
            plt.title("CPU Usage Over Time")
            plt.xlabel("Timestamp")
            plt.ylabel("CPU Usage (%)")
            plt.legend()
            plt.tight_layout()
            plt.show()
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            hide_loading()

    threading.Thread(target=task).start()


def analyze_login_attempts():
    def task():
        file_path = filedialog.askopenfilename(title="Select Login Log CSV")
        if not file_path:
            return

        try:
            show_loading("Analyzing login logs...")
            time.sleep(1)

            data = pd.read_csv(file_path)
            data['failed'] = data['status'] == 'failure'
            data['fail_streak'] = data['failed'].astype(int).groupby(
                (data['failed'] != data['failed'].shift()).cumsum()).cumsum()
            data['is_anomaly'] = data['fail_streak'] >= LOGIN_FAILURE_THRESHOLD
            data.to_csv('login_anomaly_output.csv', index=False)

            messagebox.showinfo("Done", f"{data['is_anomaly'].sum()} suspicious events saved to login_anomaly_output.csv")

            plt.figure(figsize=(8, 4))
            normal = data[data['is_anomaly'] == False]
            anomaly = data[data['is_anomaly'] == True]
            plt.plot(normal['timestamp'], [1]*len(normal), 'go', label='Normal')
            plt.plot(anomaly['timestamp'], [1]*len(anomaly), 'ro', label='Anomaly')
            plt.xticks(rotation=45)
            plt.title("Login Events")
            plt.xlabel("Timestamp")
            plt.yticks([])
            plt.legend()
            plt.tight_layout()
            plt.show()
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            hide_loading()

    threading.Thread(target=task).start()


import os
import sys

def reset_app():
    python = sys.executable
    os.execl(python, python, *sys.argv)

tk.Label(window, text="Cybersecurity Anomaly Detection", font=("Segoe UI", 16, "bold"), bg="#1e1e1e", fg="#00c3ff").pack(pady=15)
ttk.Button(window, text=" Analyze CPU Usage Logs", command=analyze_cpu_usage).pack(pady=6)
ttk.Button(window, text=" Analyze Login Attempt Logs", command=analyze_login_attempts).pack(pady=6)
ttk.Button(window, text=" Reset", command=reset_app).pack(pady=10)
ttk.Button(window, text=" Exit", command=window.destroy).pack(pady=5)

window.mainloop()
