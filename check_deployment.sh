#!/bin/bash

# Quick deployment status checker

echo "🔍 Checking Deployment Status..."
echo ""

# Check running containers
echo "📦 Running Containers:"
sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.CreatedAt}}" | head -10
echo ""

# Check recent containers (including stopped)
echo "📋 Recent Containers (Last 5):"
sudo docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.CreatedAt}}" | head -6
echo ""

# Check for build processes
echo "🔨 Docker Build Processes:"
ps aux | grep "docker.*build" | grep -v grep || echo "No active builds"
echo ""

# Check Docker daemon status
echo "🐳 Docker Daemon Status:"
sudo systemctl is-active docker && echo "✅ Docker is running" || echo "❌ Docker is not running"
echo ""

# Check disk space
echo "💾 Disk Space:"
df -h / | tail -1 | awk '{print "Available: " $4 " / Total: " $2}'
echo ""

# Check recent logs
echo "📝 Recent Container Logs (Last 10 lines from most recent container):"
LATEST_CONTAINER=$(sudo docker ps -a --format "{{.Names}}" | head -1)
if [ -n "$LATEST_CONTAINER" ]; then
    echo "Container: $LATEST_CONTAINER"
    sudo docker logs --tail 10 "$LATEST_CONTAINER" 2>&1 | tail -10
else
    echo "No containers found"
fi
echo ""
echo "✅ Status check complete!"
echo ""
echo "💡 To follow logs in real-time:"
echo "   sudo docker logs -f <container_name>"

