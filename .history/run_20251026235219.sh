#!/bin/bash

# Kyber DHT Visualization App Launcher
echo "🔐 Starting Kyber Quantum-Safe DHT Messaging App..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install requirements if not already installed
echo "📦 Installing dependencies..."
pip install -r requirements.txt

echo "🚀 Launching Streamlit app..."
streamlit run kyber2.py --server.port 8501 --server.address 0.0.0.0
