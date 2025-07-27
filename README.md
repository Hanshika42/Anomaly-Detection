# Cybersecurity Anomaly Detection Tool
A simple GUI-based Python tool to detect CPU usage spikes and suspicious login behavior from CSV log data.

## Features
- Detects unusual CPU activity and login attempts
- Visualizes anomalies with color-coded graphs
- Beginner-friendly GUI with dark mode
- CSV-based input and output
- Fake login for realistic touch
- Reset and exit buttons with animations

## How It Works
1.Load a CPU or Login CSV file using the GUI
2.The tool scans for abnormal patterns
3.Results are shown visually and saved to output files

## Built With
- Python 3
- Tkinter (GUI)
- pandas (Data analysis)
- matplotlib (Graphs)

## Sample Files

Use the test CSVs in the assets/ folder:
-sample_cpu_log.csv
-sample_login_log.csv

## To Run This Tool

1.Install the required packages:
   
   ```bash
   pip install -r requirements.txt
