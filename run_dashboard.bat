@echo off
echo Starting SentinelOne Dashboard...

:: 1. Force kill existing processes to clear the port
taskkill /F /IM streamlit.exe >nul 2>&1
taskkill /F /IM ngrok.exe >nul 2>&1
taskkill /F /IM python.exe >nul 2>&1

echo Old processes cleaned up.

:: 2. Start Streamlit in the background
echo Launching Streamlit App...
start /min /B "" "C:\Users\Favour.ESENTRY\AppData\Local\anaconda3\python.exe" -m streamlit run "C:\Users\Favour.ESENTRY\Desktop\Automation\automation_app.py" --server.port 8501 --server.headless true

:: Wait for Streamlit to initialize
timeout /t 5 /nobreak >nul

:: 3. Start Ngrok Tunnel
echo Launching Ngrok Tunnel...
start /min /B "" "C:\Users\Favour.ESENTRY\Desktop\Automation\ngrok.exe" http --domain=eve-unsubordinative-hye.ngrok-free.dev 8501

echo.
echo ========================================================
echo   DASHBOARD IS LIVE!
echo   Local URL: http://localhost:8501
echo   Public URL: https://eve-unsubordinative-hye.ngrok-free.dev/
echo ========================================================
echo.
echo DO NOT CLOSE THIS WINDOW. You can minimize it.
pause
