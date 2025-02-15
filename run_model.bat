@echo off
cd /d c:\ransomware-detection
call Scripts\activate.bat
python main.py --test-model --test-duration 300
pause