#include <iostream>
#include <iomanip>
#include <sstream>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <ctime>
#include <string>
#include <vector>

// Helper function to convert bytes to hex string
std::string bytesToHex(const unsigned char* bytes, size_t length) {
    std::stringstream ss;
    for (size_t i = 0; i < length; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i];
    }
    return ss.str();
}

// Helper function to generate an OTP
std::string generateOTP(const std::string& secret, time_t timestamp) {
    const size_t TOTP_INTERVAL = 30; // OTP validity interval in seconds
    unsigned char key[32]; // Secret key size
    memset(key, 0, sizeof(key));

    // Fill key with the secret (simplified for this example)
    std::copy(secret.begin(), secret.end(), key);

    // Calculate the time interval
    unsigned long time_interval = timestamp / TOTP_INTERVAL;

    // Convert time interval to bytes
    unsigned char time_bytes[8];
    for (int i = 0; i < 8; ++i) {
        time_bytes[i] = (time_interval >> (56 - 8 * i)) & 0xFF;
    }

    // Generate HMAC-SHA1 hash
    unsigned char hmac_result[SHA_DIGEST_LENGTH];
    HMAC(EVP_sha1(), key, sizeof(key), time_bytes, sizeof(time_bytes), hmac_result, nullptr);

    // Truncate hash to 6-digit OTP
    unsigned int offset = hmac_result[SHA_DIGEST_LENGTH - 1] & 0x0F;
    unsigned int binary_code = (hmac_result[offset] & 0x7F) << 24 |
                               (hmac_result[offset + 1] & 0xFF) << 16 |
                               (hmac_result[offset + 2] & 0xFF) << 8 |
                               (hmac_result[offset + 3] & 0xFF);

    // Generate OTP
    const unsigned int OTP_LENGTH = 6;
    unsigned int otp = binary_code % static_cast<unsigned int>(pow(10, OTP_LENGTH));
    std::stringstream otp_ss;
    otp_ss << std::setw(OTP_LENGTH) << std::setfill('0') << otp;

    return otp_ss.str();
}

// Function to validate the OTP
bool validateOTP(const std::string& secret, const std::string& otp_to_check, time_t timestamp) {
    std::string generated_otp = generateOTP(secret, timestamp);
    return generated_otp == otp_to_check;
}

int main() {
    // Example secret key (base32 encoded secret)
    std::string secret = "12345678901234567890123456789012"; // Replace with your actual secret key

    // Generate an OTP
    time_t current_time = std::time(nullptr);
    std::string otp = generateOTP(secret, current_time);
    std::cout << "Generated OTP: " << otp << std::endl;

    // Validate the OTP (for example, input from user)
    std::string otp_to_check;
    std::cout << "Enter OTP to validate: ";
    std::cin >> otp_to_check;

    if (validateOTP(secret, otp_to_check, current_time)) {
        std::cout << "OTP is valid!" << std::endl;
    } else {
        std::cout << "Invalid OTP!" << std::endl;
    }

    return 0;
}
