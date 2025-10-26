#!/bin/bash

# Kyber DHT Visualization App Launcher
echo "🔐 Starting Kyber Quantum-Safe DHT Messaging App..."
echo "📦 Installing dependencies..."

# Install requirements if not already installed
pip install -r requirements.txt

echo "🚀 Launching Streamlit app..."
streamlit run kyber2.py --server.port 8501 --server.address 0.0.0.0
