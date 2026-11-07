import engine
from unittest.mock import patch

with patch("engine.requests.post", side_effect=engine.requests.Timeout("Simulated timeout")) as mock_post:
    try:
        engine.local_chat("Test log entry", timeout=1)
        print("TEST FAILED")
    except engine.ModelError:
        assert mock_post.call_count == 2
        print("TIMEOUT AND RETRY TEST PASSED")