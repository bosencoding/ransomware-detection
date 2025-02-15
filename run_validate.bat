@echo off
cd /d c:\ransomware-detection
call Scripts\activate.bat
python main.py --validate-only
pause