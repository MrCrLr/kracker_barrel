import numpy as np
from multiprocessing.shared_memory import SharedMemory

def test_shared_memory_write_read():
    batch_size = 5
    max_password_size = 20
    passwords = ["password1", "password2", "password3"]

    # Create shared memory
    shared_memory_size = batch_size * max_password_size
    shm = SharedMemory(create=True, size=shared_memory_size)

    try:
        shared_array = np.ndarray((batch_size, max_password_size), dtype=np.uint8, buffer=shm.buf)

        # Write passwords to shared memory
        for i, password in enumerate(passwords):
            password_bytes = password.encode('utf-8')
            shared_array[i, :len(password_bytes)] = np.frombuffer(password_bytes, dtype=np.uint8)
            shared_array[i, len(password_bytes):] = 0  # Pad with zeros
            print(f"Written password at index {i}: {password}")

        # Clear unused rows
        for i in range(len(passwords), batch_size):
            shared_array[i, :] = 0
            print(f"Cleared row {i} in shared memory.")

        # Read passwords from shared memory
        for i, row in enumerate(shared_array):
            raw_data = row.tobytes()
            password = raw_data.split(b'\x00', 1)[0].decode('utf-8')
            print(f"Read password at index {i}: {password}")

    finally:
        shm.close()
        shm.unlink()

test_shared_memory_write_read()