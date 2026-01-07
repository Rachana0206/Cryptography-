@echo off
echo 🔐 Starting Comprehensive Cryptography Toolkit Web Server...
echo.
echo 📱 Website will be available at: http://localhost:5000
echo 🔌 API will be available at: http://localhost:5000/api
echo 📊 Health check: http://localhost:5000/api/health
echo 🎯 Demo: http://localhost:5000/api/demo
echo.
echo Press Ctrl+C to stop the server
echo.
python server.py
pause
