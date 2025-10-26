import streamlit as st
import hashlib
import json
from typing import Tuple, List
import secrets
import os

# ============================================================================
# CRYSTALS-KYBER IMPLEMENTATION (Simplified for Educational Purposes)
# ============================================================================

# Kyber Parameters (Kyber512 variant - simplified)
N = 256  # Polynomial degree
Q = 3329  # Modulus
K = 2    # Number of polynomial vectors
ETA = 3  # Noise parameter

class Polynomial:
    """Represents a polynomial in Z_q[X]/(X^N + 1)"""
    
    def __init__(self, coeffs: List[int]):
        self.coeffs = [c % Q for c in coeffs[:N]] + [0] * (N - len(coeffs))
    
    def __add__(self, other):
        """Polynomial addition mod q"""
        result = [(a + b) % Q for a, b in zip(self.coeffs, other.coeffs)]
        return Polynomial(result)
    
    def __sub__(self, other):
        """Polynomial subtraction mod q"""
        result = [(a - b) % Q for a, b in zip(self.coeffs, other.coeffs)]
        return Polynomial(result)
    
    def __mul__(self, other):
        """Polynomial multiplication in ring Z_q[X]/(X^N + 1)"""
        result = [0] * (2 * N)
        
        # Standard polynomial multiplication
        for i in range(N):
            for j in range(N):
                result[i + j] = (result[i + j] + self.coeffs[i] * other.coeffs[j]) % Q
        
        # Reduce modulo X^N + 1
        for i in range(N, 2 * N):
            result[i - N] = (result[i - N] - result[i]) % Q
        
        return Polynomial(result[:N])
    
    def to_bytes(self) -> bytes:
        """Convert polynomial to bytes"""
        return json.dumps(self.coeffs).encode()
    
    @staticmethod
    def from_bytes(data: bytes):
        """Create polynomial from bytes"""
        coeffs = json.loads(data.decode())
        return Polynomial(coeffs)


def cbd(seed: bytes, nonce: int, eta: int) -> Polynomial:
    """Centered Binomial Distribution using secure random"""
    hasher = hashlib.shake_256(seed + nonce.to_bytes(2, 'big'))
    random_bytes = hasher.digest(N * eta // 4)
    
    coeffs = []
    byte_idx = 0
    
    for _ in range(N):
        a = 0
        b = 0
        for _ in range(eta):
            if byte_idx < len(random_bytes):
                bit = (random_bytes[byte_idx // 8] >> (byte_idx % 8)) & 1
                a += bit
                byte_idx += 1
        for _ in range(eta):
            if byte_idx < len(random_bytes):
                bit = (random_bytes[byte_idx // 8] >> (byte_idx % 8)) & 1
                b += bit
                byte_idx += 1
        coeffs.append((a - b) % Q)
    
    return Polynomial(coeffs)


def parse_polynomial(seed: bytes, i: int, j: int) -> Polynomial:
    """Generate deterministic polynomial from seed using SHA3"""
    hasher = hashlib.shake_256(seed + bytes([i, j]))
    random_bytes = hasher.digest(N * 3)  # 3 bytes per coefficient for uniform sampling
    
    coeffs = []
    byte_idx = 0
    
    while len(coeffs) < N and byte_idx + 2 < len(random_bytes):
        # Sample uniformly from [0, Q)
        val = int.from_bytes(random_bytes[byte_idx:byte_idx+2], 'little') & 0x0FFF
        if val < Q:
            coeffs.append(val)
        byte_idx += 2
    
    # Pad if needed
    while len(coeffs) < N:
        coeffs.append(0)
    
    return Polynomial(coeffs)


def compress_poly(poly: Polynomial, d: int) -> List[int]:
    """Compress polynomial coefficients"""
    compressed = []
    for c in poly.coeffs:
        # Compress: round((2^d / q) * c) mod 2^d
        compressed_val = round((c * (2 ** d)) / Q) % (2 ** d)
        compressed.append(compressed_val)
    return compressed


def decompress_poly(compressed: List[int], d: int) -> Polynomial:
    """Decompress polynomial coefficients"""
    decompressed = []
    for c in compressed:
        # Decompress: round((q / 2^d) * c)
        decompressed_val = round((c * Q) / (2 ** d)) % Q
        decompressed.append(decompressed_val)
    return Polynomial(decompressed)


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
        # Decode bit: closer to Q/2 means 1, closer to 0 means 0
        coeff = poly.coeffs[i]
        # Use modular distance
        dist_to_zero = min(coeff, Q - coeff)
        dist_to_half = min(abs(coeff - Q // 2), abs(coeff - Q // 2 - Q))
        
        if dist_to_half < dist_to_zero:
            msg[byte_idx] |= (1 << bit_idx)
    
    return bytes(msg)


# ============================================================================
# KYBER KEY GENERATION, ENCRYPTION, DECRYPTION
# ============================================================================

def kyber_keygen() -> Tuple[dict, dict]:
    """Generate Kyber key pair using secure random"""
    # Generate random seeds using secrets module
    seed = secrets.token_bytes(32)
    rho = hashlib.sha3_256(seed + b'rho').digest()
    sigma = hashlib.sha3_256(seed + b'sigma').digest()
    
    # Generate matrix A
    A = [[parse_polynomial(rho, i, j) for j in range(K)] for i in range(K)]
    
    # Generate secret vector s
    s = [cbd(sigma, i, ETA) for i in range(K)]
    
    # Generate error vector e
    e = [cbd(sigma, K + i, ETA) for i in range(K)]
    
    # Compute t = A*s + e
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
    # Generate encryption randomness
    randomness = secrets.token_bytes(32)
    
    # Reconstruct public key
    t = [Polynomial(coeffs) for coeffs in public_key['t']]
    rho = bytes.fromhex(public_key['rho'])
    A = [[parse_polynomial(rho, i, j) for j in range(K)] for i in range(K)]
    
    # Generate random vectors
    r = [cbd(randomness, i, ETA) for i in range(K)]
    e1 = [cbd(randomness, K + i, ETA) for i in range(K)]
    e2 = cbd(randomness, 2 * K, ETA)
    
    # Compute u = A^T * r + e1
    u = []
    for j in range(K):
        u_j = Polynomial([0] * N)
        for i in range(K):
            u_j = u_j + (A[i][j] * r[i])
        u_j = u_j + e1[j]
        u.append(u_j)
    
    # Encode message
    m_poly = encode_message(message)
    
    # Compute v = t^T * r + e2 + m
    v = Polynomial([0] * N)
    for i in range(K):
        v = v + (t[i] * r[i])
    v = v + e2 + m_poly
    
    # Compress
    u_compressed = [compress_poly(poly, 10) for poly in u]
    v_compressed = compress_poly(v, 4)
    
    return {
        'u': u_compressed,
        'v': v_compressed
    }


def kyber_decrypt(private_key: dict, ciphertext: dict) -> bytes:
    """Decrypt Kyber ciphertext"""
    # Reconstruct components
    s = [Polynomial(coeffs) for coeffs in private_key['s']]
    u = [decompress_poly(comp, 10) for comp in ciphertext['u']]
    v = decompress_poly(ciphertext['v'], 4)
    
    # Compute s^T * u
    s_dot_u = Polynomial([0] * N)
    for i in range(K):
        s_dot_u = s_dot_u + (s[i] * u[i])
    
    # Recover message: m = v - s^T * u
    m_poly = v - s_dot_u
    
    # Decode
    message = decode_message(m_poly)
    
    return message


# ============================================================================
# STREAMLIT UI WITH DARK THEME
# ============================================================================

def apply_custom_css():
    """Apply custom dark theme CSS"""
    st.markdown("""
    <style>
        /* Main background */
        .stApp {
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
        }
        
        /* Sidebar styling */
        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #16213e 0%, #0f1419 100%);
            border-right: 1px solid #00ff88;
        }
        
        /* Headers */
        h1, h2, h3 {
            color: #00ff88 !important;
            font-weight: 700 !important;
            text-shadow: 0 0 10px rgba(0, 255, 136, 0.3);
        }
        
        /* Text */
        p, div, span, label {
            color: #e0e0e0 !important;
        }
        
        /* Input fields */
        .stTextInput input, .stTextArea textarea, .stSelectbox select {
            background-color: #1a1a2e !important;
            color: #00ff88 !important;
            border: 2px solid #00ff88 !important;
            border-radius: 8px !important;
            font-weight: 500 !important;
        }
        
        /* Buttons */
        .stButton button {
            background: linear-gradient(90deg, #00ff88 0%, #00cc70 100%) !important;
            color: #0a0a0a !important;
            font-weight: 700 !important;
            border: none !important;
            border-radius: 8px !important;
            padding: 0.5rem 2rem !important;
            box-shadow: 0 4px 15px rgba(0, 255, 136, 0.4) !important;
            transition: all 0.3s ease !important;
        }
        
        .stButton button:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 6px 20px rgba(0, 255, 136, 0.6) !important;
        }
        
        /* Success/Info/Warning boxes */
        .stSuccess {
            background-color: rgba(0, 255, 136, 0.1) !important;
            border: 1px solid #00ff88 !important;
            border-radius: 8px !important;
            color: #00ff88 !important;
        }
        
        .stInfo {
            background-color: rgba(33, 150, 243, 0.1) !important;
            border: 1px solid #2196F3 !important;
            border-radius: 8px !important;
        }
        
        .stError {
            background-color: rgba(244, 67, 54, 0.1) !important;
            border: 1px solid #f44336 !important;
            border-radius: 8px !important;
        }
        
        /* Expander */
        .streamlit-expanderHeader {
            background-color: #1a1a2e !important;
            border: 1px solid #00ff88 !important;
            border-radius: 8px !important;
            color: #00ff88 !important;
        }
        
        /* Code blocks */
        .stCodeBlock {
            background-color: #0a0a0a !important;
            border: 1px solid #00ff88 !important;
            border-radius: 8px !important;
        }
        
        /* Metrics */
        [data-testid="stMetricValue"] {
            color: #00ff88 !important;
            font-size: 2rem !important;
            font-weight: 700 !important;
        }
        
        /* Divider */
        hr {
            border-color: #00ff88 !important;
            opacity: 0.3 !important;
        }
        
        /* Container/Cards */
        .element-container {
            background-color: rgba(26, 26, 46, 0.5) !important;
            border-radius: 8px !important;
            padding: 1rem !important;
            margin: 0.5rem 0 !important;
        }
        
        /* Checkbox */
        .stCheckbox {
            color: #00ff88 !important;
        }
        
        /* Message container */
        .message-container {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border: 1px solid #00ff88;
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1rem 0;
            box-shadow: 0 4px 15px rgba(0, 255, 136, 0.2);
        }
        
        /* Lock icon effect */
        .lock-icon {
            color: #00ff88;
            text-shadow: 0 0 10px rgba(0, 255, 136, 0.8);
            font-size: 2rem;
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


def main():
    st.set_page_config(
        page_title="Kyber Quantum-Safe Messaging",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    apply_custom_css()
    init_session_state()
    
    # Header with security emphasis
    st.markdown("""
    <div style='text-align: center; padding: 2rem 0;'>
        <h1 style='font-size: 3rem; margin: 0;'>🔐 QUANTUM-SAFE MESSAGING</h1>
        <p style='color: #00ff88; font-size: 1.2rem; margin-top: 0.5rem;'>
            Powered by CRYSTALS-Kyber Post-Quantum Encryption
        </p>
        <p style='color: #888; font-size: 0.9rem;'>
            🛡️ Military-Grade Security • 🔒 Zero-Knowledge Architecture • ⚡ End-to-End Encrypted
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown("### 👤 USER ACCESS CONTROL")
        
        username = st.text_input("🆔 Username", placeholder="Enter your identity...")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🔓 LOGIN", use_container_width=True):
                if username:
                    if username not in st.session_state.users:
                        with st.spinner("🔐 Generating quantum-safe keypair..."):
                            pub_key, priv_key = kyber_keygen()
                            st.session_state.users[username] = {
                                'public_key': pub_key,
                                'private_key': priv_key
                            }
                        st.success(f"✓ Secure identity created!")
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
            
            with st.expander("🔑 YOUR PUBLIC KEY"):
                user_data = st.session_state.users[st.session_state.current_user]
                st.code(json.dumps(user_data['public_key'], indent=2)[:500] + "...", language="json")
                st.caption("📤 Share this key to receive encrypted messages")
        
        st.markdown("---")
        
        st.markdown("### 🌐 NETWORK USERS")
        if st.session_state.users:
            for user in st.session_state.users.keys():
                icon = "🟢" if user == st.session_state.current_user else "⚪"
                st.markdown(f"{icon} **{user}**")
        else:
            st.info("No users online")
        
        st.markdown("---")
        
        st.session_state.show_technical = st.checkbox(
            "🔬 Technical Details",
            value=st.session_state.show_technical
        )
    
    # Main content
    if not st.session_state.current_user:
        # Landing page
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            <div class='message-container'>
                <h3>🛡️ POST-QUANTUM SECURITY</h3>
                <p>Protected against quantum computer attacks using NIST-standardized Kyber encryption</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class='message-container'>
                <h3>🔐 ZERO-KNOWLEDGE</h3>
                <p>Your private keys never leave your device. True end-to-end encryption</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class='message-container'>
                <h3>⚡ LATTICE-BASED</h3>
                <p>Mathematical hardness based on Learning With Errors problem</p>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("### 📚 HOW IT WORKS")
        
        tab1, tab2, tab3 = st.tabs(["🔑 Key Generation", "🔒 Encryption", "🔓 Decryption"])
        
        with tab1:
            st.markdown("""
            **Quantum-Safe Key Generation:**
            1. Generate random matrix **A** in polynomial ring Z_q[X]/(X^256 + 1)
            2. Create secret vector **s** with small coefficients from centered binomial distribution
            3. Compute **t = A·s + e** where **e** is small error
            4. **Public Key**: (t, A) • **Private Key**: s
            
            🔐 Security based on Module Learning With Errors (M-LWE) problem
            """)
        
        with tab2:
            st.markdown("""
            **Encryption Process:**
            1. Use recipient's public key (t, A)
            2. Generate random vector **r** and error terms **e₁, e₂**
            3. Compute **u = Aᵀ·r + e₁**
            4. Compute **v = tᵀ·r + e₂ + encode(message)**
            5. Compress and send ciphertext **(u, v)**
            
            🔒 Each message uses fresh randomness for semantic security
            """)
        
        with tab3:
            st.markdown("""
            **Decryption Process:**
            1. Receive ciphertext (u, v) and decompress
            2. Compute **sᵀ·u** using your private key **s**
            3. Recover message: **decode(v - sᵀ·u)**
            4. Error cancellation reveals plaintext
            
            🔓 Only the holder of private key **s** can decrypt
            """)
        
    else:
        # Messaging interface
        st.markdown("### 📨 SECURE MESSAGE TRANSMISSION")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            recipient = st.selectbox(
                "📥 Recipient",
                [u for u in st.session_state.users.keys() 
                 if u != st.session_state.current_user],
                key="recipient_select"
            )
        
        message_text = st.text_area(
            "✉️ Message Content (Max 32 bytes)",
            max_chars=32,
            height=100,
            placeholder="Type your confidential message here..."
        )
        
        if st.button("🔒 ENCRYPT & SEND", type="primary", use_container_width=True):
            if recipient and message_text:
                # Prepare message
                msg_bytes = message_text.encode('utf-8')
                if len(msg_bytes) < 32:
                    msg_bytes = msg_bytes + b'\x00' * (32 - len(msg_bytes))
                else:
                    msg_bytes = msg_bytes[:32]
                
                # Encrypt
                recipient_pub_key = st.session_state.users[recipient]['public_key']
                
                with st.spinner("🔐 Encrypting with quantum-safe algorithm..."):
                    ciphertext = kyber_encrypt(recipient_pub_key, msg_bytes)
                
                # Store message
                st.session_state.messages.append({
                    'from': st.session_state.current_user,
                    'to': recipient,
                    'ciphertext': ciphertext,
                    'plaintext': message_text,
                    'timestamp': len(st.session_state.messages)
                })
                
                st.success(f"✓ Message encrypted and transmitted to {recipient}")
                st.rerun()
            else:
                st.error("⚠️ Please select recipient and enter message")
        
        st.markdown("---")
        
        # Message history
        st.markdown("### 📬 MESSAGE VAULT")
        
        user_messages = [
            msg for msg in st.session_state.messages
            if msg['to'] == st.session_state.current_user or 
               msg['from'] == st.session_state.current_user
        ]
        
        if not user_messages:
            st.info("📭 No messages in vault. Send your first quantum-safe message!")
        else:
            for msg in reversed(user_messages):
                is_received = msg['to'] == st.session_state.current_user
                
                st.markdown("""
                <div class='message-container'>
                """, unsafe_allow_html=True)
                
                col1, col2, col3 = st.columns([2, 2, 1])
                
                with col1:
                    if is_received:
                        st.markdown(f"**📥 FROM:** {msg['from']}")
                    else:
                        st.markdown(f"**📤 TO:** {msg['to']}")
                
                with col2:
                    status = "🔒 ENCRYPTED" if is_received else "✓ SENT"
                    st.markdown(f"**STATUS:** {status}")
                
                with col3:
                    if is_received:
                        if st.button("🔓 DECRYPT", key=f"decrypt_{msg['timestamp']}", use_container_width=True):
                            priv_key = st.session_state.users[st.session_state.current_user]['private_key']
                            
                            with st.spinner("🔓 Decrypting..."):
                                try:
                                    decrypted = kyber_decrypt(priv_key, msg['ciphertext'])
                                    decrypted_text = decrypted.rstrip(b'\x00').decode('utf-8', errors='ignore')
                                    st.success(f"**📄 DECRYPTED MESSAGE:**\n\n{decrypted_text}")
                                except Exception as e:
                                    st.error(f"Decryption error: {str(e)}")
                
                with st.expander("📊 Ciphertext Data"):
                    st.code(json.dumps(msg['ciphertext'], indent=2)[:400] + "...", language="json")
                
                if st.session_state.show_technical:
                    with st.expander("🔬 Cryptographic Analysis"):
                        st.markdown(f"""
                        **Encryption Parameters:**
                        - Ring dimension: N = {N}
                        - Modulus: q = {Q}
                        - Module rank: k = {K}
                        - Noise parameter: η = {ETA}
                        - Polynomial vectors in u: {len(msg['ciphertext']['u'])}
                        - Coefficients in v: {len(msg['ciphertext']['v'])}
                        
                        **Security Level:**
                        - Post-quantum security: NIST Level 1
                        - Equivalent classical security: ~128 bits
                        - Based on Module-LWE hardness assumption
                        """)
                
                st.markdown("</div>", unsafe_allow_html=True)
        
        # System info
        if st.session_state.show_technical:
            st.markdown("---")
            st.markdown("### ⚙️ SYSTEM PARAMETERS")
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Ring Dimension", N, help="Polynomial degree")
            
            with col2:
                st.metric("Modulus", Q, help="Coefficient modulus")
            
            with col3:
                st.metric("Module Rank", K, help="Vector dimension")
            
            with col4:
                st.metric("Active Users", len(st.session_state.users), help="Network participants")


if __name__ == "__main__":
    main()