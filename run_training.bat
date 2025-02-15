@echo off
cd /d c:\ransomware-detection
call Scripts\activate.bat
python main.py --train-for-metrics
pause