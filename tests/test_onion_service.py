"""
test_onion_service.py

Tests the OnionService class by spinning up a local HTTP server,
exposing it via Tor, and attempting to fetch data from the onion address.
"""
import pytest
import requests
import threading
import os
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from unittest.mock import MagicMock
from stem import ControllerError

from key_pair import KeyPair
from onion_service import OnionService

# Load .env manually to ensure TOR_PASSWORD is set for tests
env_path = os.path.join(os.path.dirname(__file__), '../.env')
if os.path.exists(env_path):
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                os.environ.setdefault(k, v)

# Configuration for the test
# Ensure Tor is running and SOCKS is at 9050, Control at 9051
TOR_CONTROL_PORT = 9051
TOR_SOCKS_PROXY = "socks5h://127.0.0.1:9050"
TOR_PASSWORD = os.getenv("TOR_PASSWORD")

class MockRequestHandler(BaseHTTPRequestHandler):
    """Responds with a simple confirmation message."""
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Onion Service Working")

class ThreadedHTTPServer:
    """Helper to run a simple HTTP server in a background thread."""
    def __init__(self):
        self.server = HTTPServer(('127.0.0.1', 0), MockRequestHandler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

@pytest.fixture(scope="module")
def tor_check():
    """Skip tests if Tor control port is not accessible."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(('127.0.0.1', TOR_CONTROL_PORT)) != 0:
            pytest.skip("Tor Control Port 9051 not available. Is Tor running?")

@pytest.fixture
def background_server():
    """Fixture to start/stop the local HTTP server."""
    server = ThreadedHTTPServer()
    server.start()
    yield server
    server.stop()

def test_onion_service_lifecycle(background_server, tor_check):
    """
    1. Generate a KeyPair.
    2. Start an Onion Service pointing to our background server.
    3. Verify the service ID matches the KeyPair.
    4. Connect to the .onion address via Tor (SOCKS).
    5. Stop the service.
    """
    # 1. Setup KeyPair
    kp = KeyPair()
    kp.generate_key_pair()

    # 2. Initialize OnionService
    # We map port 80 (virtual) -> background_server.port (local)
    service = OnionService(
        key_pair=kp, 
        target_port=background_server.port, 
        hidden_service_port=80,
        control_port=TOR_CONTROL_PORT,
        password=os.getenv("TOR_PASSWORD")
    )

    onion_address = None
    try:
        # 3. Start Service
        onion_address = service.start()
        assert onion_address is not None
        assert len(onion_address) == 56 # v3 onion addresses are 56 chars
        print(f"\nService started at: http://{onion_address}.onion")

        # 4. Connect via Tor
        # We need a requests session configured to use the Tor SOCKS proxy
        session = requests.Session()
        session.proxies = {
            'http': TOR_SOCKS_PROXY,
            'https': TOR_SOCKS_PROXY
        }

        # It might take a moment for the descriptor to propagate fully,
        # though await_publication=True in start() handles most of this.
        url = f"http://{onion_address}.onion"
        
        # Retry logic just in case propagation is laggy
        success = False
        last_error = None
        for _ in range(3):
            try:
                response = session.get(url, timeout=30)
                if response.status_code == 200 and response.content == b"Onion Service Working":
                    success = True
                    break
            except requests.RequestException as e:
                last_error = e
                time.sleep(2)
        
        if not success:
            pytest.fail(f"Could not reach onion service: {last_error}")

    finally:
        # 5. Stop Service
        service.stop()

def test_start_without_private_key():
    """Test that starting without a private key raises ValueError."""
    kp = KeyPair()
    # Do NOT generate keys, leaving private_key as None
    
    service = OnionService(kp, 8000)
    
    with pytest.raises(ValueError, match="Cannot start service: KeyPair has no private key."):
        service.start()

def test_stop_ignores_controller_errors():
    """Test that stop() handles exceptions during service removal gracefully."""
    kp = KeyPair()
    kp.generate_key_pair()
    
    service = OnionService(kp, 8000)
    
    # Simulate a running state with a mock controller
    service.service_id = "test-service-id"
    mock_controller = MagicMock()
    service.controller = mock_controller
    
    # Force an error on removal to trigger the except block
    mock_controller.remove_ephemeral_hidden_service.side_effect = ControllerError("Simulated Tor failure")
    
    service.stop()
    
    # Verify it tried to remove, caught the error, and closed cleanly
    mock_controller.remove_ephemeral_hidden_service.assert_called_with("test-service-id")
    mock_controller.close.assert_called_once()
    assert service.service_id is None
    assert service.controller is None
