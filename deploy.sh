#!/bin/bash
set -e

echo "Deploying CloudGuard Posture Monitor..."

# Check for Docker
if ! command -v docker &> /dev/null
then
    echo "Docker not found. Please install Docker and Docker Compose first."
    exit 1
fi

echo "Building and starting Docker services..."
docker-compose up -d --build

echo "Deployment complete! CloudGuard is now running."
echo "- Grafana: http://localhost:3000 (No login required)"
echo "- Prometheus: http://localhost:9090"
echo "- Pushgateway: http://localhost:9091"
echo ""
echo "To view logs for the scanner:"
echo "docker-compose logs -f scanner"
