import numpy as np
import matplotlib.pyplot as plt
from scipy.interpolate import make_interp_spline


def plot_aes_performance():
    block_sizes = np.array([16, 32, 48, 64, 80, 96, 112, 128])

    throughput_128 = np.array([600, 850, 950, 1100, 1300, 1450, 1600, 1800])
    throughput_192 = np.array([500, 720, 830, 950, 1150, 1300, 1450, 1650])
    throughput_256 = np.array([400, 600, 700, 800, 950, 1100, 1200, 1350])

    block_sizes_smooth = np.linspace(block_sizes.min(), block_sizes.max(), 200)

    spl_128 = make_interp_spline(block_sizes, throughput_128, k=3)
    throughput_128_smooth = spl_128(block_sizes_smooth)

    spl_192 = make_interp_spline(block_sizes, throughput_192, k=3)
    throughput_192_smooth = spl_192(block_sizes_smooth)

    spl_256 = make_interp_spline(block_sizes, throughput_256, k=3)
    throughput_256_smooth = spl_256(block_sizes_smooth)

    plt.figure(figsize=(8, 5))
    plt.plot(block_sizes_smooth, throughput_128_smooth, color='blue', label='AES-128', linewidth=2)
    plt.plot(block_sizes_smooth, throughput_192_smooth, color='green', label='AES-192', linewidth=2)
    plt.plot(block_sizes_smooth, throughput_256_smooth, color='red', label='AES-256', linewidth=2)

    plt.title('AES Performance: Block Size vs Throughput')
    plt.xlabel('Block Size (bytes)')
    plt.ylabel('Throughput (KB/s)')
    plt.legend()
    plt.grid(True)
    plt.show()


def plot_rsa_performance():
    rsa_key_sizes = np.array([512, 1024, 1536, 2048])

    sign_throughput = np.array([300, 250, 200, 150])
    verify_throughput = np.array([10000, 16000, 25000, 35000])

    key_sizes_smooth = np.linspace(rsa_key_sizes.min(), rsa_key_sizes.max(), 300)

    spl_sign = make_interp_spline(rsa_key_sizes, sign_throughput, k=3)
    sign_smooth = spl_sign(key_sizes_smooth)

    spl_verify = make_interp_spline(rsa_key_sizes, verify_throughput, k=3)
    verify_smooth = spl_verify(key_sizes_smooth)

    plt.figure(figsize=(8, 5))
    plt.plot(key_sizes_smooth, sign_smooth, label='Sign', color='blue', linewidth=2)
    plt.plot(key_sizes_smooth, verify_smooth, label='Verify', color='orange', linewidth=2)

    plt.title('RSA Performance: Key Size vs Throughput')
    plt.xlabel('RSA Key Size (bits)')
    plt.ylabel('Throughput (operations/s)')
    plt.legend()
    plt.grid(True)
    plt.show()


def main():
    plot_aes_performance()

    plot_rsa_performance()

if __name__ == "__main__":
    main()
