import base64
import math
from multiprocessing import Pool

# XOR utility function
def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

# LCG class
class LCG:
    def __init__(self, a, b, state=0):
        self.a = a
        self.b = b
        self.mod = 2 ** 16
        self.state = state

    def next(self):
        self.state = (self.a * self.state + self.b) % self.mod
        return self.state

# Test a range of b values
def test_b_range(params):
    start_b, end_b, states = params
    print(f"Testing range: b={start_b} to b={end_b}", flush=True)
    for b in range(start_b, end_b):
        if b % 100 == 0:
            print(f"Currently testing b={b}", flush=True)
        for i in range(len(states) - 1):
            s_i = states[i]
            s_next = states[i + 1]
            try:
                a = (s_next - b) * pow(s_i, -1, 2**16) % 2**16
            except ValueError:
                continue  # Skip if modular inverse doesn't exist

            # Increased range for initial_state
            for initial_state in range(0, 5000):  # Increased from 1000 to 5000
                lcg = LCG(a, b, state=initial_state)
                generated_states = [lcg.next() for _ in range(len(states))]
                if generated_states == states:
                    print(f"Match Found: b={b}, a={a}, initial_state={initial_state}", flush=True)
                    return a, b, initial_state
    return None

# Function to recover LCG parameters using multiprocessing
def recover_lcg_params_parallel(ciphertext, known_plaintext, num_processes=8):
    partial_key = xor(ciphertext[:len(known_plaintext)], known_plaintext.encode())
    print(f"Partial Key (Hex): {partial_key.hex()}", flush=True)
    states = [
        int.from_bytes(partial_key[i:i+2], "little")
        for i in range(0, len(partial_key), 2)
    ]
    print(f"Extracted States: {states}", flush=True)

    # Split b range into chunks for parallel processing
    total_b = 10000 - 1337
    chunk_size = total_b // num_processes
    ranges = [(1337 + i * chunk_size, 1337 + (i + 1) * chunk_size, states) for i in range(num_processes)]

    # Process ranges in parallel
    with Pool(processes=num_processes) as pool:
        results = pool.map(test_b_range, ranges)
        for result in results:
            if result:
                return result
    return None, None, None

# Main function to retrieve ciphertext, recover parameters, and decrypt
def main():
    # Base64-encoded ciphertext from the server
    ciphertext_base64 = "YmtdR6OhXAc+/ZWxbMMZw3m2wT3cnIg1YcMFqEM0qMNvwG9GghN5hZoDp2xoLSRX/Hf89Pui4AiCjCMKcpSFhLfjk+X3asoEiEn8tJird3+dOx0ORPw98INjaBGX"
    ciphertext = base64.b64decode(ciphertext_base64)

    # Known plaintext for XOR decryption
    known_plaintext = (
        "Stay your hand! Gotcha!\nYou do not know this part, \n"
    )

    # Recover parameters using parallelized brute force
    a, b, initial_state = recover_lcg_params_parallel(ciphertext, known_plaintext, num_processes=8)
    if a is not None:
        print(f"Recovered Parameters: a={a}, b={b}, initial_state={initial_state}", flush=True)
        
        # Use the recovered parameters to generate the full key and decrypt
        lcg = LCG(a, b, state=initial_state)
        full_key = b"".join(
            lcg.next().to_bytes(2, "little")
            for _ in range(math.ceil(len(ciphertext) / 2))
        )
        plaintext = xor(ciphertext, full_key).decode("ASCII", errors="ignore")
        print("Decrypted Plaintext:\n", plaintext, flush=True)
    else:
        print("Failed to recover LCG parameters.", flush=True)

# Run the main function
if __name__ == "__main__":
    main()
