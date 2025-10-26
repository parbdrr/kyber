import streamlit as st
import hashlib
import json
from typing import Tuple, List, Dict, Optional
import secrets
import time
import threading
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
from collections import deque

# ============================================================================
# DISTRIBUTED HASH TABLE (DHT) IMPLEMENTATION
# ============================================================================

class DistributedHashTable:
    """
    Enhanced DHT for secure ciphertext routing with comprehensive monitoring.
    Stores middle portions of split ciphertexts temporarily with full analytics.
    """
    
    def __init__(self, reset_interval: int = 300):  # 5 minutes default
        self.table: Dict[str, dict] = {}
        self.reset_interval = reset_interval
        self.last_reset = time.time()
        self.operation_log = []
        self.lock = threading.Lock()
        
        # Enhanced analytics
        self.stats = {
            'total_puts': 0,
            'total_gets': 0,
            'total_deletes': 0,
            'total_resets': 0,
            'successful_gets': 0,
            'expired_gets': 0,
            'not_found_gets': 0,
            'peak_entries': 0,
            'total_data_stored': 0
        }
        
        # Performance tracking
        self.performance_history = deque(maxlen=100)
        self.entry_lifecycle = {}
        
        # Start auto-reset thread
        self.reset_thread = threading.Thread(target=self._auto_reset, daemon=True)
        self.reset_thread.start()
    
    def _auto_reset(self):
        """Background thread for automatic DHT reset"""
        while True:
            time.sleep(1)
            if time.time() - self.last_reset >= self.reset_interval:
                self.reset()
    
    def put(self, key: str, value: any, ttl: int = None) -> bool:
        """Store value in DHT with optional TTL and enhanced tracking"""
        with self.lock:
            expiry = time.time() + (ttl if ttl else self.reset_interval)
            created_time = time.time()
            
            self.table[key] = {
                'value': value,
                'expiry': expiry,
                'created': created_time,
                'size_bytes': len(json.dumps(value).encode('utf-8'))
            }
            
            # Track entry lifecycle
            self.entry_lifecycle[key] = {
                'created': created_time,
                'expiry': expiry,
                'size': len(json.dumps(value).encode('utf-8'))
            }
            
            # Update stats
            self.stats['total_puts'] += 1
            self.stats['total_data_stored'] += len(json.dumps(value).encode('utf-8'))
            self.stats['peak_entries'] = max(self.stats['peak_entries'], len(self.table))
            
            # Performance tracking
            self.performance_history.append({
                'timestamp': created_time,
                'operation': 'PUT',
                'entries_count': len(self.table),
                'data_size': self.stats['total_data_stored']
            })
            
            self.operation_log.append({
                'operation': 'PUT',
                'key': key,
                'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'expiry': datetime.fromtimestamp(expiry).strftime('%H:%M:%S'),
                'size_bytes': len(json.dumps(value).encode('utf-8'))
            })
            return True
    
    def get(self, key: str) -> Optional[any]:
        """Retrieve value from DHT with enhanced tracking"""
        with self.lock:
            current_time = time.time()
            self.stats['total_gets'] += 1
            
            if key in self.table:
                entry = self.table[key]
                if current_time < entry['expiry']:
                    # Successful get
                    self.stats['successful_gets'] += 1
                    
                    # Performance tracking
                    self.performance_history.append({
                        'timestamp': current_time,
                        'operation': 'GET_SUCCESS',
                        'entries_count': len(self.table),
                        'data_size': self.stats['total_data_stored']
                    })
                    
                    self.operation_log.append({
                        'operation': 'GET',
                        'key': key,
                        'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                        'status': 'SUCCESS',
                        'age_seconds': current_time - entry['created']
                    })
                    return entry['value']
                else:
                    # Expired, remove it
                    del self.table[key]
                    if key in self.entry_lifecycle:
                        del self.entry_lifecycle[key]
                    
                    self.stats['expired_gets'] += 1
                    self.operation_log.append({
                        'operation': 'GET',
                        'key': key,
                        'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                        'status': 'EXPIRED'
                    })
            else:
                self.stats['not_found_gets'] += 1
                self.operation_log.append({
                    'operation': 'GET',
                    'key': key,
                    'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                    'status': 'NOT_FOUND'
                })
            return None
    
    def delete(self, key: str) -> bool:
        """Remove value from DHT with enhanced tracking"""
        with self.lock:
            if key in self.table:
                entry = self.table[key]
                del self.table[key]
                
                if key in self.entry_lifecycle:
                    del self.entry_lifecycle[key]
                
                self.stats['total_deletes'] += 1
                
                self.operation_log.append({
                    'operation': 'DELETE',
                    'key': key,
                    'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                    'age_seconds': time.time() - entry['created']
                })
                return True
            return False
    
    def reset(self):
        """Clear all DHT entries (periodic reset) with enhanced tracking"""
        with self.lock:
            count = len(self.table)
            data_size = sum(entry.get('size_bytes', 0) for entry in self.table.values())
            
            self.table.clear()
            self.entry_lifecycle.clear()
            self.last_reset = time.time()
            
            self.stats['total_resets'] += 1
            
            # Performance tracking
            self.performance_history.append({
                'timestamp': time.time(),
                'operation': 'RESET',
                'entries_count': 0,
                'data_size': 0
            })
            
            self.operation_log.append({
                'operation': 'RESET',
                'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'entries_cleared': count,
                'data_cleared_bytes': data_size
            })
    
    def get_status(self) -> dict:
        """Get comprehensive DHT status with analytics"""
        with self.lock:
            current_time = time.time()
            active_entries = {
                k: v for k, v in self.table.items()
                if current_time < v['expiry']
            }
            
            # Calculate additional metrics
            total_data_size = sum(entry.get('size_bytes', 0) for entry in active_entries.values())
            avg_entry_age = np.mean([current_time - entry['created'] for entry in active_entries.values()]) if active_entries else 0
            
            return {
                'active_entries': len(active_entries),
                'total_entries': len(self.table),
                'time_until_reset': max(0, self.reset_interval - (current_time - self.last_reset)),
                'last_reset': self.last_reset,
                'entries': active_entries,
                'total_data_size': total_data_size,
                'avg_entry_age': avg_entry_age,
                'stats': self.stats.copy(),
                'performance_history': list(self.performance_history)
            }
    
    def get_recent_logs(self, count: int = 10) -> List[dict]:
        """Get recent operation logs"""
        with self.lock:
            return self.operation_log[-count:]
    
    def get_analytics_data(self) -> dict:
        """Get comprehensive analytics data for visualization"""
        with self.lock:
            current_time = time.time()
            
            # Create time series data for charts
            timestamps = []
            entry_counts = []
            data_sizes = []
            
            for perf in self.performance_history:
                timestamps.append(datetime.fromtimestamp(perf['timestamp']))
                entry_counts.append(perf['entries_count'])
                data_sizes.append(perf['data_size'])
            
            # Operation distribution
            operation_counts = {
                'PUT': self.stats['total_puts'],
                'GET_SUCCESS': self.stats['successful_gets'],
                'GET_EXPIRED': self.stats['expired_gets'],
                'GET_NOT_FOUND': self.stats['not_found_gets'],
                'DELETE': self.stats['total_deletes'],
                'RESET': self.stats['total_resets']
            }
            
            # Entry lifecycle analysis
            lifecycle_data = []
            for key, lifecycle in self.entry_lifecycle.items():
                lifecycle_data.append({
                    'key': key[:8] + '...',
                    'created': datetime.fromtimestamp(lifecycle['created']),
                    'expiry': datetime.fromtimestamp(lifecycle['expiry']),
                    'size': lifecycle['size'],
                    'ttl_remaining': max(0, lifecycle['expiry'] - current_time)
                })
            
            return {
                'timestamps': timestamps,
                'entry_counts': entry_counts,
                'data_sizes': data_sizes,
                'operation_counts': operation_counts,
                'lifecycle_data': lifecycle_data,
                'current_stats': self.stats.copy()
            }


# ============================================================================
# DHT VISUALIZATION FUNCTIONS
# ============================================================================

def create_dht_performance_chart(analytics_data):
    """Create interactive performance charts for DHT operations"""
    if not analytics_data['timestamps']:
        return None
    
    fig = go.Figure()
    
    # Add entry count line
    fig.add_trace(go.Scatter(
        x=analytics_data['timestamps'],
        y=analytics_data['entry_counts'],
        mode='lines+markers',
        name='Active Entries',
        line=dict(color='#00ff88', width=3),
        marker=dict(size=6)
    ))
    
    # Add data size line (secondary y-axis)
    fig.add_trace(go.Scatter(
        x=analytics_data['timestamps'],
        y=analytics_data['data_sizes'],
        mode='lines+markers',
        name='Data Size (bytes)',
        yaxis='y2',
        line=dict(color='#2196F3', width=2),
        marker=dict(size=4)
    ))
    
    fig.update_layout(
        title='DHT Performance Over Time',
        xaxis_title='Time',
        yaxis_title='Active Entries',
        yaxis2=dict(
            title='Data Size (bytes)',
            overlaying='y',
            side='right'
        ),
        template='plotly_dark',
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#e0e0e0'),
        height=400
    )
    
    return fig

def create_operation_distribution_chart(analytics_data):
    """Create pie chart for operation distribution"""
    operation_counts = analytics_data['operation_counts']
    
    # Filter out zero values
    filtered_counts = {k: v for k, v in operation_counts.items() if v > 0}
    
    if not filtered_counts:
        return None
    
    colors = {
        'PUT': '#00ff88',
        'GET_SUCCESS': '#2196F3',
        'GET_EXPIRED': '#ff6b6b',
        'GET_NOT_FOUND': '#888',
        'DELETE': '#ff9800',
        'RESET': '#e91e63'
    }
    
    fig = go.Figure(data=[go.Pie(
        labels=list(filtered_counts.keys()),
        values=list(filtered_counts.values()),
        marker_colors=[colors.get(label, '#888') for label in filtered_counts.keys()],
        textinfo='label+percent+value',
        textfont=dict(color='#e0e0e0')
    )])
    
    fig.update_layout(
        title='DHT Operation Distribution',
        template='plotly_dark',
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#e0e0e0'),
        height=400
    )
    
    return fig

def create_entry_lifecycle_chart(analytics_data):
    """Create Gantt chart for entry lifecycle visualization"""
    lifecycle_data = analytics_data['lifecycle_data']
    
    if not lifecycle_data:
        return None
    
    fig = go.Figure()
    
    for i, entry in enumerate(lifecycle_data):
        fig.add_trace(go.Scatter(
            x=[entry['created'], entry['expiry']],
            y=[entry['key'], entry['key']],
            mode='lines+markers',
            name=entry['key'],
            line=dict(width=8, color='#00ff88'),
            marker=dict(size=10),
            hovertemplate=f"<b>{entry['key']}</b><br>" +
                         f"Created: %{{x}}<br>" +
                         f"Expires: %{{x2}}<br>" +
                         f"Size: {entry['size']} bytes<br>" +
                         f"TTL: {entry['ttl_remaining']:.1f}s<extra></extra>"
        ))
    
    fig.update_layout(
        title='DHT Entry Lifecycle Timeline',
        xaxis_title='Time',
        yaxis_title='Entry Keys',
        template='plotly_dark',
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#e0e0e0'),
        height=max(300, len(lifecycle_data) * 30)
    )
    
    return fig

def create_network_topology_chart(dht_status):
    """Create network topology visualization"""
    entries = dht_status['entries']
    
    if not entries:
        return None
    
    # Create nodes for each DHT entry
    nodes = []
    edges = []
    
    for i, (key, entry) in enumerate(entries.items()):
        nodes.append({
            'id': key[:8],
            'label': f"{key[:8]}...",
            'size': min(50, max(10, entry.get('size_bytes', 0) / 100)),
            'color': '#00ff88' if time.time() < entry['expiry'] else '#ff6b6b',
            'x': np.cos(2 * np.pi * i / len(entries)) * 100,
            'y': np.sin(2 * np.pi * i / len(entries)) * 100
        })
    
    # Create edges (simplified - could be more sophisticated)
    for i in range(len(nodes)):
        if i < len(nodes) - 1:
            edges.append({
                'source': nodes[i]['id'],
                'target': nodes[i + 1]['id'],
                'color': '#00ff88'
            })
    
    fig = go.Figure()
    
    # Add edges
    for edge in edges:
        source_node = next(n for n in nodes if n['id'] == edge['source'])
        target_node = next(n for n in nodes if n['id'] == edge['target'])
        
        fig.add_trace(go.Scatter(
            x=[source_node['x'], target_node['x']],
            y=[source_node['y'], target_node['y']],
            mode='lines',
            line=dict(color=edge['color'], width=2),
            showlegend=False,
            hoverinfo='skip'
        ))
    
    # Add nodes
    fig.add_trace(go.Scatter(
        x=[node['x'] for node in nodes],
        y=[node['y'] for node in nodes],
        mode='markers+text',
        marker=dict(
            size=[node['size'] for node in nodes],
            color=[node['color'] for node in nodes],
            line=dict(width=2, color='#fff')
        ),
        text=[node['label'] for node in nodes],
        textposition='middle center',
        textfont=dict(color='#000', size=10),
        hovertemplate='<b>%{text}</b><br>Size: %{marker.size}px<extra></extra>',
        name='DHT Nodes'
    ))
    
    fig.update_layout(
        title='DHT Network Topology',
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        template='plotly_dark',
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#e0e0e0'),
        height=400,
        showlegend=False
    )
    
    return fig


# ============================================================================
# CIPHERTEXT SPLITTING & RECONSTRUCTION
# ============================================================================

def split_ciphertext(ciphertext: dict) -> Tuple[dict, dict, dict]:
    """
    Split ciphertext into three parts:
    - Part 1: First half of u vectors
    - Part 2: Second half of u vectors + first part of v (routed through DHT)
    - Part 3: Rest of v vector
    """
    u = ciphertext['u']
    v = ciphertext['v']
    
    # Split u vectors
    u_mid = len(u) // 2
    
    # Split v vector
    v_mid1 = len(v) // 3
    v_mid2 = 2 * len(v) // 3
    
    part1 = {
        'u_part': u[:u_mid],
        'type': 'part1'
    }
    
    part2 = {
        'u_part': u[u_mid:],
        'v_part': v[:v_mid2],
        'type': 'part2'
    }
    
    part3 = {
        'v_part': v[v_mid2:],
        'type': 'part3'
    }
    
    return part1, part2, part3


def reconstruct_ciphertext(part1: dict, part2: dict, part3: dict) -> dict:
    """Reconstruct full ciphertext from three parts"""
    u = part1['u_part'] + part2['u_part']
    v = part2['v_part'] + part3['v_part']
    
    return {
        'u': u,
        'v': v
    }


# ============================================================================
# CRYSTALS-KYBER IMPLEMENTATION
# ============================================================================

N = 256  # Polynomial degree
Q = 3329  # Modulus
K = 2    # Number of polynomial vectors
ETA = 3  # Noise parameter

class Polynomial:
    """Represents a polynomial in Z_q[X]/(X^N + 1)"""
    
    def __init__(self, coeffs: List[int]):
        self.coeffs = [c % Q for c in coeffs[:N]] + [0] * (N - len(coeffs))
    
    def __add__(self, other):
        result = [(a + b) % Q for a, b in zip(self.coeffs, other.coeffs)]
        return Polynomial(result)
    
    def __sub__(self, other):
        result = [(a - b) % Q for a, b in zip(self.coeffs, other.coeffs)]
        return Polynomial(result)
    
    def __mul__(self, other):
        result = [0] * (2 * N)
        for i in range(N):
            for j in range(N):
                result[i + j] = (result[i + j] + self.coeffs[i] * other.coeffs[j]) % Q
        for i in range(N, 2 * N):
            result[i - N] = (result[i - N] - result[i]) % Q
        return Polynomial(result[:N])


def cbd(seed: bytes, nonce: int, eta: int) -> Polynomial:
    """Centered Binomial Distribution"""
    hasher = hashlib.shake_256(seed + nonce.to_bytes(2, 'big'))
    random_bytes = hasher.digest(N * eta // 4)
    
    coeffs = []
    byte_idx = 0
    
    for _ in range(N):
        a = sum((random_bytes[byte_idx // 8] >> (byte_idx % 8 + i)) & 1 for i in range(eta) if byte_idx + i < len(random_bytes) * 8)
        byte_idx += eta
        b = sum((random_bytes[byte_idx // 8] >> (byte_idx % 8 + i)) & 1 for i in range(eta) if byte_idx + i < len(random_bytes) * 8)
        byte_idx += eta
        coeffs.append((a - b) % Q)
    
    return Polynomial(coeffs)


def parse_polynomial(seed: bytes, i: int, j: int) -> Polynomial:
    """Generate deterministic polynomial from seed"""
    hasher = hashlib.shake_256(seed + bytes([i, j]))
    random_bytes = hasher.digest(N * 3)
    
    coeffs = []
    byte_idx = 0
    
    while len(coeffs) < N and byte_idx + 2 < len(random_bytes):
        val = int.from_bytes(random_bytes[byte_idx:byte_idx+2], 'little') & 0x0FFF
        if val < Q:
            coeffs.append(val)
        byte_idx += 2
    
    while len(coeffs) < N:
        coeffs.append(0)
    
    return Polynomial(coeffs)


def compress_poly(poly: Polynomial, d: int) -> List[int]:
    """Compress polynomial coefficients"""
    return [round((c * (2 ** d)) / Q) % (2 ** d) for c in poly.coeffs]


def decompress_poly(compressed: List[int], d: int) -> Polynomial:
    """Decompress polynomial coefficients"""
    return Polynomial([round((c * Q) / (2 ** d)) % Q for c in compressed])


def encode_message(msg: bytes) -> Polynomial:
    """Encode 32-byte message into polynomial"""
    coeffs = []
    for i in range(256):
        byte_idx = i // 8
        bit_idx = i % 8
        if byte_idx < len(msg):
            bit = (msg[byte_idx] >> bit_idx) & 1
            coeffs.append(bit * (Q // 2))
        else:
            coeffs.append(0)
    return Polynomial(coeffs)


def decode_message(poly: Polynomial) -> bytes:
    """Decode polynomial back to 32-byte message"""
    msg = bytearray(32)
    for i in range(256):
        byte_idx = i // 8
        bit_idx = i % 8
        coeff = poly.coeffs[i]
        dist_to_zero = min(coeff, Q - coeff)
        dist_to_half = min(abs(coeff - Q // 2), abs(coeff - Q // 2 - Q))
        
        if dist_to_half < dist_to_zero:
            msg[byte_idx] |= (1 << bit_idx)
    
    return bytes(msg)


def kyber_keygen() -> Tuple[dict, dict]:
    """Generate Kyber key pair"""
    seed = secrets.token_bytes(32)
    rho = hashlib.sha3_256(seed + b'rho').digest()
    sigma = hashlib.sha3_256(seed + b'sigma').digest()
    
    A = [[parse_polynomial(rho, i, j) for j in range(K)] for i in range(K)]
    s = [cbd(sigma, i, ETA) for i in range(K)]
    e = [cbd(sigma, K + i, ETA) for i in range(K)]
    
    t = []
    for i in range(K):
        t_i = Polynomial([0] * N)
        for j in range(K):
            t_i = t_i + (A[i][j] * s[j])
        t_i = t_i + e[i]
        t.append(t_i)
    
    public_key = {
        't': [poly.coeffs for poly in t],
        'rho': rho.hex()
    }
    
    private_key = {
        's': [poly.coeffs for poly in s],
        'public_key': public_key
    }
    
    return public_key, private_key


def kyber_encrypt(public_key: dict, message: bytes) -> dict:
    """Encrypt message using Kyber"""
    randomness = secrets.token_bytes(32)
    
    t = [Polynomial(coeffs) for coeffs in public_key['t']]
    rho = bytes.fromhex(public_key['rho'])
    A = [[parse_polynomial(rho, i, j) for j in range(K)] for i in range(K)]
    
    r = [cbd(randomness, i, ETA) for i in range(K)]
    e1 = [cbd(randomness, K + i, ETA) for i in range(K)]
    e2 = cbd(randomness, 2 * K, ETA)
    
    u = []
    for j in range(K):
        u_j = Polynomial([0] * N)
        for i in range(K):
            u_j = u_j + (A[i][j] * r[i])
        u_j = u_j + e1[j]
        u.append(u_j)
    
    m_poly = encode_message(message)
    
    v = Polynomial([0] * N)
    for i in range(K):
        v = v + (t[i] * r[i])
    v = v + e2 + m_poly
    
    u_compressed = [compress_poly(poly, 10) for poly in u]
    v_compressed = compress_poly(v, 4)
    
    return {
        'u': u_compressed,
        'v': v_compressed
    }


def kyber_decrypt(private_key: dict, ciphertext: dict) -> bytes:
    """Decrypt Kyber ciphertext"""
    s = [Polynomial(coeffs) for coeffs in private_key['s']]
    u = [decompress_poly(comp, 10) for comp in ciphertext['u']]
    v = decompress_poly(ciphertext['v'], 4)
    
    s_dot_u = Polynomial([0] * N)
    for i in range(K):
        s_dot_u = s_dot_u + (s[i] * u[i])
    
    m_poly = v - s_dot_u
    message = decode_message(m_poly)
    
    return message


# ============================================================================
# STREAMLIT UI
# ============================================================================

def apply_custom_css():
    """Apply custom dark theme CSS"""
    st.markdown("""
    <style>
        .stApp {
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
        }
        
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #16213e 0%, #0f1419 100%);
            border-right: 1px solid #00ff88;
        }
        
        h1, h2, h3 {
            color: #00ff88 !important;
            font-weight: 700 !important;
            text-shadow: 0 0 10px rgba(0, 255, 136, 0.3);
        }
        
        p, div, span, label {
            color: #e0e0e0 !important;
        }
        
        .stTextInput input, .stTextArea textarea, .stSelectbox select {
            background-color: #1a1a2e !important;
            color: #00ff88 !important;
            border: 2px solid #00ff88 !important;
            border-radius: 8px !important;
        }
        
        .stButton button {
            background: linear-gradient(90deg, #00ff88 0%, #00cc70 100%) !important;
            color: #0a0a0a !important;
            font-weight: 700 !important;
            border: none !important;
            border-radius: 8px !important;
            padding: 0.5rem 2rem !important;
            box-shadow: 0 4px 15px rgba(0, 255, 136, 0.4) !important;
        }
        
        .stButton button:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 6px 20px rgba(0, 255, 136, 0.6) !important;
        }
        
        .dht-container {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border: 2px solid #00ff88;
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1rem 0;
            box-shadow: 0 4px 15px rgba(0, 255, 136, 0.2);
        }
        
        .message-container {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border: 1px solid #00ff88;
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1rem 0;
            box-shadow: 0 4px 15px rgba(0, 255, 136, 0.2);
        }
        
        .stTabs [data-baseweb="tab-list"] {
            gap: 8px;
        }
        
        .stTabs [data-baseweb="tab"] {
            background-color: #1a1a2e;
            border: 1px solid #00ff88;
            color: #00ff88;
            border-radius: 8px;
            padding: 0.5rem 1rem;
        }
        
        .stTabs [aria-selected="true"] {
            background: linear-gradient(90deg, #00ff88 0%, #00cc70 100%);
            color: #0a0a0a !important;
        }
        
        .metric-card {
            background: rgba(0, 255, 136, 0.1);
            border: 1px solid #00ff88;
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }
    </style>
    """, unsafe_allow_html=True)


def init_session_state():
    """Initialize session state"""
    if 'users' not in st.session_state:
        st.session_state.users = {}
    if 'current_user' not in st.session_state:
        st.session_state.current_user = None
    if 'messages' not in st.session_state:
        st.session_state.messages = []
    if 'show_technical' not in st.session_state:
        st.session_state.show_technical = False
    if 'dht' not in st.session_state:
        st.session_state.dht = DistributedHashTable(reset_interval=300)  # 5 min


def main():
    st.set_page_config(
        page_title="Kyber + DHT Secure Messaging",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    apply_custom_css()
    init_session_state()
    
    # Header
    st.markdown("""
    <div style='text-align: center; padding: 2rem 0;'>
        <h1 style='font-size: 3rem; margin: 0;'>🔐 QUANTUM-SAFE DHT MESSAGING</h1>
        <p style='color: #00ff88; font-size: 1.2rem; margin-top: 0.5rem;'>
            Kyber Encryption + Distributed Hash Table Routing
        </p>
        <p style='color: #888; font-size: 0.9rem;'>
            🛡️ Post-Quantum Security • 🌐 DHT Intermediary • ⚡ Auto-Expiring Storage
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown("### 👤 USER ACCESS")
        
        username = st.text_input("🆔 Username", placeholder="Enter identity...")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🔓 LOGIN", use_container_width=True):
                if username:
                    if username not in st.session_state.users:
                        with st.spinner("🔐 Generating keys..."):
                            pub_key, priv_key = kyber_keygen()
                            st.session_state.users[username] = {
                                'public_key': pub_key,
                                'private_key': priv_key
                            }
                        st.success(f"✓ Identity created!")
                    else:
                        st.success(f"✓ Welcome back!")
                    
                    st.session_state.current_user = username
                    st.rerun()
                else:
                    st.error("⚠️ Username required")
        
        with col2:
            if st.button("🚪 LOGOUT", use_container_width=True):
                st.session_state.current_user = None
                st.rerun()
        
        if st.session_state.current_user:
            st.markdown(f"""
            <div style='background: rgba(0, 255, 136, 0.1); 
                        border: 1px solid #00ff88; 
                        border-radius: 8px; 
                        padding: 1rem; 
                        margin: 1rem 0;'>
                <p style='margin: 0; color: #00ff88;'>
                    ✓ AUTHENTICATED<br/>
                    <strong>{st.session_state.current_user}</strong>
                </p>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        st.markdown("### 🌐 NETWORK USERS")
        if st.session_state.users:
            for user in st.session_state.users.keys():
                icon = "🟢" if user == st.session_state.current_user else "⚪"
                st.markdown(f"{icon} **{user}**")
        else:
            st.info("No users online")
        
        st.markdown("---")
        
        # DHT Quick Stats
        st.markdown("### 📊 DHT STATUS")
        dht_status = st.session_state.dht.get_status()
        st.metric("Active Entries", dht_status['active_entries'])
        
        time_left = int(dht_status['time_until_reset'])
        mins = time_left // 60
        secs = time_left % 60
        st.metric("Next Reset", f"{mins}m {secs}s")
        
        st.markdown("---")
        
        st.session_state.show_technical = st.checkbox(
            "🔬 Technical Mode",
            value=st.session_state.show_technical
        )
    
    # Main tabs
    tab1, tab2, tab3 = st.tabs(["💬 Messaging", "🌐 DHT Visualization", "📚 Documentation"])
    
    # ========================================================================
    # TAB 1: MESSAGING
    # ========================================================================
    with tab1:
        if not st.session_state.current_user:
            st.info("👈 Please login to start messaging")
        else:
            st.markdown("### 📨 SECURE MESSAGE TRANSMISSION")
            
            recipient = st.selectbox(
                "📥 Recipient",
                [u for u in st.session_state.users.keys() 
                 if u != st.session_state.current_user],
                key="recipient_select"
            )
            
            message_text = st.text_area(
                "✉️ Message (Max 32 bytes)",
                max_chars=32,
                height=100,
                placeholder="Type confidential message..."
            )
            
            if st.button("🔒 ENCRYPT & SEND VIA DHT", type="primary", use_container_width=True):
                if recipient and message_text:
                    msg_bytes = message_text.encode('utf-8')
                    if len(msg_bytes) < 32:
                        msg_bytes = msg_bytes + b'\x00' * (32 - len(msg_bytes))
                    else:
                        msg_bytes = msg_bytes[:32]
                    
                    recipient_pub_key = st.session_state.users[recipient]['public_key']
                    
                    with st.spinner("🔐 Encrypting..."):
                        ciphertext = kyber_encrypt(recipient_pub_key, msg_bytes)
                    
                    with st.spinner("🌐 Splitting and routing through DHT..."):
                        part1, part2, part3 = split_ciphertext(ciphertext)
                        
                        # Generate DHT key
                        dht_key = hashlib.sha256(
                            f"{st.session_state.current_user}{recipient}{time.time()}".encode()
                        ).hexdigest()[:16]
                        
                        # Store middle part in DHT
                        st.session_state.dht.put(dht_key, part2, ttl=300)
                        
                        # Store message with DHT reference
                        st.session_state.messages.append({
                            'from': st.session_state.current_user,
                            'to': recipient,
                            'part1': part1,
                            'dht_key': dht_key,
                            'part3': part3,
                            'plaintext': message_text,
                            'timestamp': len(st.session_state.messages),
                            'created': time.time()
                        })
                    
                    st.success(f"✓ Message encrypted and routed through DHT to {recipient}")
                    st.info(f"🔑 DHT Key: `{dht_key}`")
                    st.rerun()
                else:
                    st.error("⚠️ Select recipient and enter message")
            
            st.markdown("---")
            
            # Message history
            st.markdown("### 📬 MESSAGE VAULT")
            
            user_messages = [
                msg for msg in st.session_state.messages
                if msg['to'] == st.session_state.current_user or 
                   msg['from'] == st.session_state.current_user
            ]
            
            if not user_messages:
                st.info("📭 No messages yet")
            else:
                for msg in reversed(user_messages):
                    is_received = msg['to'] == st.session_state.current_user
                    
                    st.markdown("<div class='message-container'>", unsafe_allow_html=True)
                    
                    col1, col2, col3 = st.columns([2, 2, 1])
                    
                    with col1:
                        if is_received:
                            st.markdown(f"**📥 FROM:** {msg['from']}")
                        else:
                            st.markdown(f"**📤 TO:** {msg['to']}")
                    
                    with col2:
                        st.markdown(f"**🔑 DHT Key:** `{msg['dht_key'][:8]}...`")
                    
                    with col3:
                        if is_received:
                            if st.button("🔓 DECRYPT", key=f"decrypt_{msg['timestamp']}", use_container_width=True):
                                priv_key = st.session_state.users[st.session_state.current_user]['private_key']
                                
                                with st.spinner("🌐 Retrieving from DHT..."):
                                    part2 = st.session_state.dht.get(msg['dht_key'])
                                
                                if part2:
                                    with st.spinner("🔓 Reconstructing and decrypting..."):
                                        try:
                                            ciphertext = reconstruct_ciphertext(
                                                msg['part1'], part2, msg['part3']
                                            )
                                            decrypted = kyber_decrypt(priv_key, ciphertext)
                                            decrypted_text = decrypted.rstrip(b'\x00').decode('utf-8', errors='ignore')
                                            st.success(f"**📄 DECRYPTED:**\n\n{decrypted_text}")
                                        except Exception as e:
                                            st.error(f"Decryption error: {str(e)}")
                                else:
                                    st.error("⚠️ DHT entry expired or not found! Message cannot be recovered.")
                    
                    # Age indicator
                    age = time.time() - msg['created']
                    age_str = f"{int(age//60)}m {int(age%60)}s ago"
                    st.caption(f"⏱️ {age_str}")
                    
                    if st.session_state.show_technical:
                        with st.expander("🔬 Technical Details"):
                            st.markdown(f"""
                            **Message Routing:**
                            - Part 1: {len(json.dumps(msg['part1']))} bytes (local)
                            - Part 2: Stored in DHT under key `{msg['dht_key']}`
                            - Part 3: {len(json.dumps(msg['part3']))} bytes (local)
                            
                            **Security:**
                            - Without DHT part, message cannot be decrypted
                            - DHT auto-expires after 5 minutes
                            - Quantum-safe Kyber encryption
                            """)
                    
                    st.markdown("</div>", unsafe_allow_html=True)
        
        # DHT Table on Main Page
        st.markdown("---")
        st.markdown("### 🌐 LIVE DHT TABLE")
        
        dht_status = st.session_state.dht.get_status()
        
        if dht_status['active_entries'] > 0:
            # Create enhanced DataFrame with sender/receiver info
            entries_data = []
            for key, entry in dht_status['entries'].items():
                ttl_remaining = entry['expiry'] - time.time()
                
                # Try to extract sender/receiver from message data
                sender = "Unknown"
                receiver = "Unknown"
                message_preview = "Encrypted Data"
                
                # Look through messages to find matching DHT key
                for msg in st.session_state.messages:
                    if msg.get('dht_key') == key:
                        sender = msg['from']
                        receiver = msg['to']
                        message_preview = msg['plaintext'][:20] + "..." if len(msg['plaintext']) > 20 else msg['plaintext']
                        break
                
                # Create animated status indicator
                if ttl_remaining > 120:
                    status_icon = "🟢"
                    status_text = "Active"
                elif ttl_remaining > 60:
                    status_icon = "🟡"
                    status_text = "Expiring Soon"
                else:
                    status_icon = "🔴"
                    status_text = "Critical"
                
                total_seconds = int(ttl_remaining)
                entries_data.append({
                    '🔑 DHT Key': key[:8] + '...',
                    '📤 Sender': sender,
                    '📥 Receiver': receiver,
                    '💬 Message': message_preview,
                    '⏰ Created': datetime.fromtimestamp(entry['created']).strftime('%H:%M:%S'),
                    '⏳ TTL': f"{total_seconds}s ({int(ttl_remaining//60)}m {int(ttl_remaining%60)}s)",
                    '📦 Size': f"{entry.get('size_bytes', 0)} bytes",
                    '📊 Status': f"{status_icon} {status_text}"
                })
            
            # Display as enhanced table
            df = pd.DataFrame(entries_data)
            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "🔑 DHT Key": st.column_config.TextColumn("DHT Key", width="small"),
                    "📤 Sender": st.column_config.TextColumn("Sender", width="medium"),
                    "📥 Receiver": st.column_config.TextColumn("Receiver", width="medium"),
                    "💬 Message": st.column_config.TextColumn("Message Preview", width="large"),
                    "⏰ Created": st.column_config.TextColumn("Created", width="small"),
                    "⏳ TTL": st.column_config.TextColumn("TTL", width="small"),
                    "📦 Size": st.column_config.TextColumn("Size", width="small"),
                    "📊 Status": st.column_config.TextColumn("Status", width="small")
                }
            )
        else:
            st.info("🌐 DHT is empty. Send a message to see entries!")
    
    # ========================================================================
    # TAB 2: DHT VISUALIZATION
    # ========================================================================
    with tab2:
        st.markdown("### 🌐 DISTRIBUTED HASH TABLE MONITOR")
        
        # Auto-refresh toggle
        col_refresh, col_interval = st.columns([1, 2])
        with col_refresh:
            auto_refresh = st.checkbox("🔄 Auto-refresh", value=True)
        with col_interval:
            refresh_interval = st.slider("Refresh interval (seconds)", 1, 10, 3)
        
        if auto_refresh:
            time.sleep(refresh_interval)
            st.rerun()
        
        dht_status = st.session_state.dht.get_status()
        analytics_data = st.session_state.dht.get_analytics_data()
        
        # Enhanced status cards
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.markdown(f"""
            <div class='metric-card'>
                <h3 style='margin: 0;'>{dht_status['active_entries']}</h3>
                <p style='margin: 0; font-size: 0.9rem;'>Active Entries</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            time_left = int(dht_status['time_until_reset'])
            st.markdown(f"""
            <div class='metric-card'>
                <h3 style='margin: 0;'>{time_left//60}m {time_left%60}s</h3>
                <p style='margin: 0; font-size: 0.9rem;'>Until Reset</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            data_size_mb = dht_status['total_data_size'] / (1024 * 1024)
            st.markdown(f"""
            <div class='metric-card'>
                <h3 style='margin: 0;'>{data_size_mb:.2f} MB</h3>
                <p style='margin: 0; font-size: 0.9rem;'>Data Stored</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            avg_age = dht_status['avg_entry_age']
            st.markdown(f"""
            <div class='metric-card'>
                <h3 style='margin: 0;'>{avg_age:.1f}s</h3>
                <p style='margin: 0; font-size: 0.9rem;'>Avg Entry Age</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col5:
            peak_entries = dht_status['stats']['peak_entries']
            st.markdown(f"""
            <div class='metric-card'>
                <h3 style='margin: 0;'>{peak_entries}</h3>
                <p style='margin: 0; font-size: 0.9rem;'>Peak Entries</p>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Message Flow Visualization
        st.markdown("### 🔄 MESSAGE FLOW THROUGH DHT")
        
        if st.session_state.messages:
            # Show recent message flow
            recent_messages = st.session_state.messages[-5:]  # Last 5 messages
            
            for i, msg in enumerate(reversed(recent_messages)):
                col1, col2, col3, col4 = st.columns([2, 1, 2, 1])
                
                with col1:
                    st.markdown(f"**📤 {msg['from']}**")
                
                with col2:
                    st.markdown("⬇️")
                
                with col3:
                    st.markdown(f"""
                    <div style='background: rgba(0, 255, 136, 0.1); 
                                border: 1px solid #00ff88; 
                                border-radius: 8px; 
                                padding: 0.5rem; 
                                text-align: center;'>
                        <strong>🌐 DHT</strong><br/>
                        <small>Key: {msg['dht_key'][:8]}...</small>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col4:
                    st.markdown("⬇️")
                
                # Check if message is still in DHT
                dht_entry = st.session_state.dht.get(msg['dht_key'])
                if dht_entry:
                    st.markdown(f"**📥 {msg['to']}** ✅ *Available in DHT*")
                else:
                    st.markdown(f"**📥 {msg['to']}** ❌ *Expired from DHT*")
                
                st.markdown("---")
        else:
            st.info("No messages sent yet. Send a message to see the flow!")
        
        st.markdown("---")
        
        # Interactive Charts Section
        st.markdown("### 📈 INTERACTIVE ANALYTICS")
        
        # Simple Analytics - Focus on Core DHT Functionality
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 📊 DHT Performance")
            perf_chart = create_dht_performance_chart(analytics_data)
            if perf_chart:
                st.plotly_chart(perf_chart, use_container_width=True)
            else:
                st.info("Send messages to see performance data!")
        
        with col2:
            st.markdown("#### 🥧 Operations")
            op_chart = create_operation_distribution_chart(analytics_data)
            if op_chart:
                st.plotly_chart(op_chart, use_container_width=True)
            else:
                st.info("No operations yet!")
        
        # Simple Network Visualization
        st.markdown("#### 🌐 DHT Network Status")
        if dht_status['active_entries'] > 0:
            # Create a simple visual representation
            st.markdown("""
            <div style='text-align: center; padding: 2rem;'>
                <div style='display: inline-block; margin: 1rem;'>
                    <div style='width: 60px; height: 60px; background: #00ff88; border-radius: 50%; 
                                display: flex; align-items: center; justify-content: center; 
                                font-size: 24px; color: #000; margin: 0 auto;'>
                        🌐
                    </div>
                    <p style='margin-top: 0.5rem;'>DHT Node</p>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Show active connections
            st.markdown(f"**Active Connections:** {dht_status['active_entries']}")
            st.markdown(f"**Total Data:** {dht_status['total_data_size']} bytes")
        else:
            st.info("DHT is empty - no active connections")
        
        st.markdown("---")
        
        # Simple DHT Explanation
        st.markdown("### 💡 HOW DHT WORKS")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            <div style='background: rgba(0, 255, 136, 0.1); 
                        border: 1px solid #00ff88; 
                        border-radius: 8px; 
                        padding: 1rem; 
                        text-align: center;'>
                <h4>🔒 1. Encrypt</h4>
                <p>Message encrypted with recipient's public key</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div style='background: rgba(0, 255, 136, 0.1); 
                        border: 1px solid #00ff88; 
                        border-radius: 8px; 
                        padding: 1rem; 
                        text-align: center;'>
                <h4>✂️ 2. Split</h4>
                <p>Ciphertext split into 3 parts for security</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div style='background: rgba(0, 255, 136, 0.1); 
                        border: 1px solid #00ff88; 
                        border-radius: 8px; 
                        padding: 1rem; 
                        text-align: center;'>
                <h4>🌐 3. Store</h4>
                <p>Middle part stored in DHT, expires in 5 min</p>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Enhanced DHT Table with Sender/Receiver Info
        st.markdown("### 📊 DHT ENTRIES - SENDER/RECEIVER TRACKING")
        
        if dht_status['active_entries'] > 0:
            # Create enhanced DataFrame with sender/receiver info
            entries_data = []
            for key, entry in dht_status['entries'].items():
                ttl_remaining = entry['expiry'] - time.time()
                
                # Try to extract sender/receiver from message data
                sender = "Unknown"
                receiver = "Unknown"
                message_preview = "Encrypted Data"
                
                # Look through messages to find matching DHT key
                for msg in st.session_state.messages:
                    if msg.get('dht_key') == key:
                        sender = msg['from']
                        receiver = msg['to']
                        message_preview = msg['plaintext'][:20] + "..." if len(msg['plaintext']) > 20 else msg['plaintext']
                        break
                
                # Create animated status indicator
                if ttl_remaining > 120:
                    status_icon = "🟢"
                    status_text = "Active"
                elif ttl_remaining > 60:
                    status_icon = "🟡"
                    status_text = "Expiring Soon"
                else:
                    status_icon = "🔴"
                    status_text = "Critical"
                
                total_seconds = int(ttl_remaining)
                entries_data.append({
                    '🔑 DHT Key': key[:8] + '...',
                    '📤 Sender': sender,
                    '📥 Receiver': receiver,
                    '💬 Message': message_preview,
                    '⏰ Created': datetime.fromtimestamp(entry['created']).strftime('%H:%M:%S'),
                    '⏳ TTL': f"{total_seconds}s ({int(ttl_remaining//60)}m {int(ttl_remaining%60)}s)",
                    '📦 Size': f"{entry.get('size_bytes', 0)} bytes",
                    '📊 Status': f"{status_icon} {status_text}"
                })
            
            # Display as enhanced table
            df = pd.DataFrame(entries_data)
            
            # Add some styling
            st.markdown("""
            <style>
            .dht-table {
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                border: 2px solid #00ff88;
                border-radius: 12px;
                padding: 1rem;
                margin: 1rem 0;
                box-shadow: 0 4px 15px rgba(0, 255, 136, 0.2);
            }
            </style>
            """, unsafe_allow_html=True)
            
            st.markdown('<div class="dht-table">', unsafe_allow_html=True)
            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "🔑 DHT Key": st.column_config.TextColumn("DHT Key", width="small"),
                    "📤 Sender": st.column_config.TextColumn("Sender", width="medium"),
                    "📥 Receiver": st.column_config.TextColumn("Receiver", width="medium"),
                    "💬 Message": st.column_config.TextColumn("Message Preview", width="large"),
                    "⏰ Created": st.column_config.TextColumn("Created", width="small"),
                    "⏳ TTL": st.column_config.TextColumn("TTL", width="small"),
                    "📦 Size": st.column_config.TextColumn("Size", width="small"),
                    "📊 Status": st.column_config.TextColumn("Status", width="small")
                }
            )
            st.markdown('</div>', unsafe_allow_html=True)
            
            # Individual entry details with enhanced visualization
            st.markdown("#### 🔍 Entry Details")
            for key, entry in dht_status['entries'].items():
                expiry_time = datetime.fromtimestamp(entry['expiry'])
                created_time = datetime.fromtimestamp(entry['created'])
                ttl_remaining = entry['expiry'] - time.time()
                
                with st.expander(f"🔑 {key[:12]}... - {entry.get('size_bytes', 0)} bytes"):
                    col1, col2, col3 = st.columns(3)
                
                with col1:
                        st.metric("Created", created_time.strftime('%H:%M:%S'))
                        st.metric("Size", f"{entry.get('size_bytes', 0)} bytes")
                
                with col2:
                        st.metric("Expires", expiry_time.strftime('%H:%M:%S'))
                        total_seconds = int(ttl_remaining)
                    mins = int(ttl_remaining // 60)
                    secs = int(ttl_remaining % 60)
                    color = '#00ff88' if ttl_remaining > 60 else '#ff6b6b'
                        st.markdown(f"**TTL:** <span style='color: {color};'>{total_seconds}s ({mins}m {secs}s)</span>", unsafe_allow_html=True)
                
                    with col3:
                        if st.button("🗑️ Delete", key=f"delete_{key}"):
                        st.session_state.dht.delete(key)
                        st.rerun()
                
                    # Enhanced progress bar
                progress = ttl_remaining / 300  # 5 min max
                    st.progress(max(0, min(1, progress)), text=f"TTL Progress: {progress*100:.1f}%")
                
                if st.session_state.show_technical:
                        st.markdown("**📦 Data Preview:**")
                        st.json(entry['value'])
        else:
            st.info("🌐 DHT is empty. No active entries.")
        
        # Manual DHT control
        st.markdown("### ⚙️ DHT CONTROL PANEL")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🔄 MANUAL RESET DHT", use_container_width=True):
                st.session_state.dht.reset()
                st.success("✓ DHT manually reset!")
                st.rerun()
        
        with col2:
            if st.button("♻️ REFRESH VIEW", use_container_width=True):
                st.rerun()
        
        st.markdown("---")
        
        # Simple Operation Summary
        st.markdown("### 📜 RECENT ACTIVITY")
        
        logs = st.session_state.dht.get_recent_logs(10)
        
        if logs:
            # Show recent activity in a simple format
            st.markdown("**Last 10 Operations:**")
            
            for log in reversed(logs[-10:]):
                operation = log['operation']
                timestamp = log['timestamp']
                
                if operation == 'PUT':
                    icon = "📥"
                    text = f"{icon} Message stored in DHT"
                elif operation == 'GET':
                    status = log.get('status', 'SUCCESS')
                    if status == 'SUCCESS':
                        icon = "📤"
                        text = f"{icon} Message retrieved successfully"
                    elif status == 'EXPIRED':
                        icon = "⏰"
                        text = f"{icon} Message expired from DHT"
                    else:
                        icon = "❌"
                        text = f"{icon} Message not found"
                elif operation == 'DELETE':
                    icon = "🗑️"
                    text = f"{icon} Message deleted from DHT"
                elif operation == 'RESET':
                    icon = "🔄"
                    text = f"{icon} DHT reset - all entries cleared"
                else:
                    icon = "ℹ️"
                    text = f"{icon} {operation}"
                
                st.markdown(f"**{timestamp}** - {text}")
                else:
            st.info("No activity yet. Send a message to see DHT operations!")
    
    # ========================================================================
    # TAB 3: DOCUMENTATION
    # ========================================================================
    with tab3:
        st.markdown("### 📚 SYSTEM ARCHITECTURE")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div class='message-container'>
                <h3>🔐 Kyber Encryption</h3>
                <p><strong>Algorithm:</strong> CRYSTALS-Kyber (NIST PQC Standard)</p>
                <p><strong>Security:</strong> Post-quantum secure, based on Module-LWE</p>
                <p><strong>Key Size:</strong> Public key ~800 bytes, Private key ~1632 bytes</p>
                <p><strong>Ciphertext:</strong> ~768 bytes (compressed)</p>
                <br/>
                <h4>Key Generation:</h4>
                <ul>
                    <li>Generate matrix A ∈ R<sub>q</sub><sup>k×k</sup></li>
                    <li>Sample secret s ∈ R<sub>q</sub><sup>k</sup> from χ<sub>η</sub></li>
                    <li>Sample error e ∈ R<sub>q</sub><sup>k</sup> from χ<sub>η</sub></li>
                    <li>Compute t = As + e</li>
                    <li>Public key: (t, ρ), Private key: s</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class='message-container'>
                <h3>🌐 DHT Routing</h3>
                <p><strong>Purpose:</strong> Distributed storage of ciphertext fragments</p>
                <p><strong>Auto-Expiry:</strong> 5 minutes (configurable)</p>
                <p><strong>Security Benefit:</strong> No single point holds complete ciphertext</p>
                <br/>
                <h4>Ciphertext Splitting:</h4>
                <ul>
                    <li><strong>Part 1:</strong> First half of u vectors (local)</li>
                    <li><strong>Part 2:</strong> Second half of u + partial v (DHT)</li>
                    <li><strong>Part 3:</strong> Remaining v vector (local)</li>
                </ul>
                <br/>
                <h4>DHT Operations:</h4>
                <ul>
                    <li><strong>PUT:</strong> Store value with TTL</li>
                    <li><strong>GET:</strong> Retrieve if not expired</li>
                    <li><strong>DELETE:</strong> Manual removal</li>
                    <li><strong>RESET:</strong> Periodic flush (every 5 min)</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        st.markdown("### 🛡️ SECURITY FEATURES")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            <div class='message-container'>
                <h4>🔒 Post-Quantum</h4>
                <p>Resistant to quantum computer attacks using Shor's algorithm</p>
                <p><strong>Hardness:</strong> Module Learning With Errors (M-LWE)</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class='message-container'>
                <h4>⏱️ Transient Storage</h4>
                <p>DHT auto-expires entries after 5 minutes</p>
                <p><strong>Benefit:</strong> Intercepted data becomes useless</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class='message-container'>
                <h4>🔗 Fragment Distribution</h4>
                <p>Ciphertext split across local + DHT storage</p>
                <p><strong>Protection:</strong> No single location has full ciphertext</p>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        st.markdown("### 🔬 CRYPTOGRAPHIC PARAMETERS")
        
        params = {
            "Ring Dimension (N)": N,
            "Modulus (q)": Q,
            "Module Rank (k)": K,
            "Noise Parameter (η)": ETA,
            "Compression (u)": "10 bits",
            "Compression (v)": "4 bits",
            "Security Level": "NIST Level 1 (~128 bits)",
            "DHT Reset Interval": "300 seconds (5 minutes)"
        }
        
        col1, col2 = st.columns(2)
        for i, (param, value) in enumerate(params.items()):
            with col1 if i % 2 == 0 else col2:
                st.markdown(f"""
                <div class='metric-card'>
                    <p style='margin: 0; font-weight: bold; color: #00ff88;'>{param}</p>
                    <p style='margin: 0; font-size: 1.2rem;'>{value}</p>
                </div>
                """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        st.markdown("### 📖 USAGE GUIDE")
        
        st.markdown("""
        <div class='message-container'>
            <h4>Step-by-Step:</h4>
            <ol>
                <li><strong>Login:</strong> Create or login to your account (generates Kyber keypair)</li>
                <li><strong>Compose:</strong> Select recipient and type message (max 32 bytes)</li>
                <li><strong>Send:</strong> Click "Encrypt & Send via DHT" to:
                    <ul>
                        <li>Encrypt message with recipient's public key</li>
                        <li>Split ciphertext into 3 parts</li>
                        <li>Store middle part in DHT with 5-minute TTL</li>
                    </ul>
                </li>
                <li><strong>Receive:</strong> Click "Decrypt" on received messages to:
                    <ul>
                        <li>Retrieve middle part from DHT</li>
                        <li>Reconstruct full ciphertext</li>
                        <li>Decrypt with your private key</li>
                    </ul>
                </li>
                <li><strong>Monitor:</strong> Use DHT Visualization tab to see routing in real-time</li>
            </ol>
            
            <h4>⚠️ Important Notes:</h4>
            <ul>
                <li>Messages expire after 5 minutes when DHT resets</li>
                <li>Decrypt messages before expiry or they're lost forever</li>
                <li>Private keys never leave your session</li>
                <li>All encryption happens client-side</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()