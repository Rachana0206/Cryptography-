# Comprehensive Cryptography Toolkit Web Server Startup Script

Write-Host "🔐 Starting Comprehensive Cryptography Toolkit Web Server..." -ForegroundColor Cyan
Write-Host ""
Write-Host "📱 Website will be available at: http://localhost:5000" -ForegroundColor Green
Write-Host "🔌 API will be available at: http://localhost:5000/api" -ForegroundColor Green
Write-Host "📊 Health check: http://localhost:5000/api/health" -ForegroundColor Green
Write-Host "🎯 Demo: http://localhost:5000/api/demo" -ForegroundColor Green
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

try {
    python server.py
} catch {
    Write-Host "❌ Failed to start server: $_" -ForegroundColor Red
    Write-Host "Make sure you have Python and Flask installed:" -ForegroundColor Yellow
    Write-Host "pip install -r requirements.txt" -ForegroundColor White
}

Read-Host "Press Enter to exit"
