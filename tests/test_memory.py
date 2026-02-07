"""Tests for secure memory handling."""

from secure_encryption.core.memory import SecureBuffer, secure_key, secure_zero


class TestSecureZero:
    def test_zeros_bytearray(self):
        buf = bytearray(b"sensitive data here!!")
        secure_zero(buf)
        assert all(b == 0 for b in buf)

    def test_zeros_empty(self):
        buf = bytearray()
        secure_zero(buf)
        assert len(buf) == 0


class TestSecureBuffer:
    def test_context_manager_zeros(self):
        with SecureBuffer(32) as buf:
            buf.data[:] = b"A" * 32
            assert buf.data == bytearray(b"A" * 32)
        # After exit, should be zeroed
        assert all(b == 0 for b in buf.data)

    def test_close_zeros(self):
        buf = SecureBuffer(16)
        buf.data[:] = b"\xff" * 16
        buf.close()
        assert all(b == 0 for b in buf.data)

    def test_size(self):
        buf = SecureBuffer(64)
        assert len(buf.data) == 64
        buf.close()


class TestSecureKey:
    def test_yields_bytearray(self):
        """secure_key should yield a mutable bytearray, not immutable bytes."""
        key_data = b"A" * 32
        with secure_key(key_data) as key:
            assert isinstance(key, bytearray)
            assert key == bytearray(b"A" * 32)

    def test_zeros_on_exit(self):
        key_data = b"S" * 16
        holder = None
        with secure_key(key_data) as key:
            holder = key
        # After context exit, the buffer should be zeroed
        assert all(b == 0 for b in holder)
