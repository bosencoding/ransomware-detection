@echo off
cd /d c:\ransomware-detection
call Scripts\activate.bat
python main.py --collect-only
pause