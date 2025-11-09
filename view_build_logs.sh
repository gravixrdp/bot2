#!/bin/bash

# View build logs for debugging

echo "🔍 Docker Build Logs Viewer"
echo ""

# Check recent failed builds
echo "📋 Recent Containers (Last 10):"
sudo docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.CreatedAt}}" | head -11
echo ""

# Get latest container
LATEST_CONTAINER=$(sudo docker ps -a --format "{{.Names}}" | head -1)

if [ -n "$LATEST_CONTAINER" ]; then
    echo "📝 Container: $LATEST_CONTAINER"
    STATUS=$(sudo docker ps -a --format '{{.Status}}' --filter name=$LATEST_CONTAINER)
    echo "Status: $STATUS"
    echo ""
    
    # Check if container failed
    if echo "$STATUS" | grep -qi "exited\|failed\|error"; then
        echo "❌ Container Failed/Stopped"
        echo ""
        echo "📄 Error Logs:"
        sudo docker logs --tail 50 "$LATEST_CONTAINER" 2>&1 | grep -i "error\|failed\|exception\|traceback" | head -20
        echo ""
    fi
    
    echo "📄 Last 50 lines of logs:"
    sudo docker logs --tail 50 "$LATEST_CONTAINER" 2>&1 | tail -50
    echo ""
    echo "💡 To follow logs in real-time:"
    echo "   sudo docker logs -f $LATEST_CONTAINER"
    echo ""
    echo "💡 To check for errors:"
    echo "   sudo docker logs $LATEST_CONTAINER 2>&1 | grep -i error"
else
    echo "No containers found"
fi
echo ""
echo "📊 System Logs (from data/logs.txt):"
tail -20 /home/ubuntu/bot2/data/logs.txt 2>/dev/null | grep -i "build\|error\|failed" | tail -10 || echo "No system logs found"
