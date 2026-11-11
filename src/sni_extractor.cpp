#include "sni_extractor.h"
#include <cstring>
#include <algorithm>
#include <array>
#include <limits>
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace DPI {

uint16_t SNIExtractor::readUint16BE(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

uint32_t SNIExtractor::readUint24BE(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8) | data[2];
}

bool SNIExtractor::isTLSClientHello(const uint8_t* payload, size_t length) {
    if (!payload || length < 9 || payload[0] != CONTENT_TYPE_HANDSHAKE) return false;
    const uint16_t version = readUint16BE(payload + 1);
    if (version < 0x0300 || version > 0x0304) return false;
    return payload[5] == HANDSHAKE_CLIENT_HELLO &&
           static_cast<size_t>(readUint16BE(payload + 3)) <= length - 5;
}

std::optional<std::string> SNIExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isTLSClientHello(payload, length)) return std::nullopt;
    const size_t record_end = 5 + readUint16BE(payload + 3);
    size_t offset = 9;
    if (offset + 34 > record_end) return std::nullopt;
    offset += 34; // Client version and random
    if (offset >= record_end) return std::nullopt;
    size_t amount = payload[offset++];
    if (amount > record_end - offset) return std::nullopt;
    offset += amount;
    if (offset + 2 > record_end) return std::nullopt;
    amount = readUint16BE(payload + offset); offset += 2;
    if (amount > record_end - offset) return std::nullopt;
    offset += amount;
    if (offset >= record_end) return std::nullopt;
    amount = payload[offset++];
    if (amount > record_end - offset) return std::nullopt;
    offset += amount;
    if (offset + 2 > record_end) return std::nullopt;
    const size_t extensions_length = readUint16BE(payload + offset); offset += 2;
    if (extensions_length > record_end - offset) return std::nullopt;
    const size_t extensions_end = offset + extensions_length;
    while (offset + 4 <= extensions_end) {
        const uint16_t extension_type = readUint16BE(payload + offset);
        const size_t extension_length = readUint16BE(payload + offset + 2);
        offset += 4;
        if (extension_length > extensions_end - offset) return std::nullopt;
        if (extension_type == EXTENSION_SNI && extension_length >= 5) {
            const size_t list_length = readUint16BE(payload + offset);
            if (list_length + 2 > extension_length) return std::nullopt;
            size_t name_offset = offset + 2;
            const size_t list_end = name_offset + list_length;
            while (name_offset + 3 <= list_end) {
                const uint8_t name_type = payload[name_offset++];
                const size_t name_length = readUint16BE(payload + name_offset); name_offset += 2;
                if (name_length > list_end - name_offset) return std::nullopt;
                if (name_type == SNI_TYPE_HOSTNAME && name_length > 0)
                    return std::string(reinterpret_cast<const char*>(payload + name_offset), name_length);
                name_offset += name_length;
            }
        }
        offset += extension_length;
    }
    return std::nullopt;
}

std::vector<std::pair<uint16_t, std::string>> SNIExtractor::extractExtensions(
    const uint8_t*, size_t) {
    return {};
}

bool HTTPHostExtractor::isHTTPRequest(const uint8_t* payload, size_t length) {
    if (!payload || length < 4) return false;
    const char* methods[] = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
    for (const char* method : methods) if (std::memcmp(payload, method, 4) == 0) return true;
    return false;
}

std::optional<std::string> HTTPHostExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isHTTPRequest(payload, length)) return std::nullopt;
    for (size_t i = 0; i + 5 < length; ++i) {
        if (std::tolower(static_cast<unsigned char>(payload[i])) == 'h' && std::tolower(static_cast<unsigned char>(payload[i + 1])) == 'o' &&
            std::tolower(static_cast<unsigned char>(payload[i + 2])) == 's' && std::tolower(static_cast<unsigned char>(payload[i + 3])) == 't' && payload[i + 4] == ':') {
            size_t start = i + 5;
            while (start < length && (payload[start] == ' ' || payload[start] == '\t')) ++start;
            size_t end = start;
            while (end < length && payload[end] != '\r' && payload[end] != '\n') ++end;
            if (end == start) return std::nullopt;
            std::string host(reinterpret_cast<const char*>(payload + start), end - start);
            const size_t colon = host.find(':');
            if (colon != std::string::npos) host.resize(colon);
            return host;
        }
    }
    return std::nullopt;
}

bool DNSExtractor::isDNSQuery(const uint8_t* payload, size_t length) {
    return payload && length >= 12 && !(payload[2] & 0x80) &&
           ((static_cast<uint16_t>(payload[4]) << 8) | payload[5]) > 0;
}

std::optional<std::string> DNSExtractor::extractQuery(const uint8_t* payload, size_t length) {
    if (!isDNSQuery(payload, length)) return std::nullopt;
    size_t offset = 12;
    std::string domain;
    while (offset < length) {
        const uint8_t label_length = payload[offset++];
        if (label_length == 0) break;
        if (label_length > 63 || label_length > length - offset) return std::nullopt;
        if (!domain.empty()) domain += '.';
        domain.append(reinterpret_cast<const char*>(payload + offset), label_length);
        offset += label_length;
    }
    return domain.empty() ? std::nullopt : std::optional<std::string>(domain);
}

namespace {
uint64_t readQuicVarInt(const uint8_t* data, size_t length, size_t& offset, bool& ok) {
    if (offset >= length) { ok = false; return 0; }
    const size_t bytes = size_t(1) << (data[offset] >> 6);
    if (bytes > length - offset) { ok = false; return 0; }
    uint64_t value = data[offset] & 0x3f;
    for (size_t i = 1; i < bytes; ++i) value = (value << 8) | data[offset + i];
    offset += bytes;
    return value;
}

bool hkdfExpandLabel(const uint8_t* secret, size_t secret_length, const std::string& label,
                     uint8_t* output, size_t output_length) {
    const std::string full_label = "tls13 " + label;
    if (full_label.size() > 255 || output_length > 65535) return false;
    std::vector<uint8_t> info;
    info.push_back(static_cast<uint8_t>(output_length >> 8));
    info.push_back(static_cast<uint8_t>(output_length));
    info.push_back(static_cast<uint8_t>(full_label.size()));
    info.insert(info.end(), full_label.begin(), full_label.end());
    info.push_back(0); // Empty context
    std::array<uint8_t, EVP_MAX_MD_SIZE> block{};
    unsigned int block_length = 0;
    std::vector<uint8_t> previous;
    size_t written = 0;
    for (uint8_t counter = 1; written < output_length; ++counter) {
        std::vector<uint8_t> input(previous);
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter);
        if (!HMAC(EVP_sha256(), secret, static_cast<int>(secret_length), input.data(), input.size(), block.data(), &block_length)) return false;
        previous.assign(block.begin(), block.begin() + block_length);
        const size_t take = std::min(output_length - written, static_cast<size_t>(block_length));
        std::copy_n(block.data(), take, output + written);
        written += take;
        if (counter == 255 && written < output_length) return false;
    }
    return true;
}

bool hkdfExtract(const uint8_t* salt, size_t salt_length, const uint8_t* input, size_t input_length,
                 uint8_t* output) {
    unsigned int written = 0;
    return HMAC(EVP_sha256(), salt, static_cast<int>(salt_length), input, input_length, output, &written) != nullptr && written == 32;
}

std::optional<std::string> sniFromQuicCrypto(const uint8_t* crypto, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        bool ok = true;
        const uint8_t frame_type = crypto[offset++];
        if (frame_type == 0x00) continue; // PADDING
        if (frame_type != 0x06) return std::nullopt; // CRYPTO frame
        const uint64_t crypto_offset = readQuicVarInt(crypto, length, offset, ok);
        const uint64_t crypto_length = readQuicVarInt(crypto, length, offset, ok);
        if (!ok || crypto_offset != 0 || crypto_length > length - offset) return std::nullopt;
        const uint8_t* handshake = crypto + offset;
        if (crypto_length >= 4 && handshake[0] == 0x01) {
            std::vector<uint8_t> tls(5, 0);
            tls[0] = 0x16; tls[1] = 0x03; tls[2] = 0x03;
            const size_t hs_length = std::min<uint64_t>(crypto_length, 0xffff);
            tls[3] = static_cast<uint8_t>(hs_length >> 8); tls[4] = static_cast<uint8_t>(hs_length);
            tls.insert(tls.end(), handshake, handshake + hs_length);
            return SNIExtractor::extract(tls.data(), tls.size());
        }
        return std::nullopt;
    }
    return std::nullopt;
}
}

bool QUICSNIExtractor::isQUICInitial(const uint8_t* payload, size_t length) {
    if (!payload || length < 6 || (payload[0] & 0xc0) != 0xc0) return false;
    const uint32_t version = (static_cast<uint32_t>(payload[1]) << 24) |
        (static_cast<uint32_t>(payload[2]) << 16) | (static_cast<uint32_t>(payload[3]) << 8) | payload[4];
    const uint8_t packet_type = (payload[0] >> 4) & 0x03;
    return version != 0 && packet_type == (version == 0x6b3343cf ? 1 : 0); // v2 uses type 1 for Initial
}

std::optional<std::string> QUICSNIExtractor::extract(const uint8_t* payload, size_t length) {
    // QUIC Initial packets require header-protection removal and AES-GCM decryption.
    if (!isQUICInitial(payload, length)) return std::nullopt;
    const uint32_t version = (static_cast<uint32_t>(payload[1]) << 24) |
        (static_cast<uint32_t>(payload[2]) << 16) | (static_cast<uint32_t>(payload[3]) << 8) | payload[4];
    static constexpr uint8_t v1_salt[] = {0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a};
    static constexpr uint8_t v2_salt[] = {0x0d,0xed,0xe3,0xde,0xf7,0x00,0xa6,0xdb,0x81,0x93,0x81,0xbe,0x6e,0x26,0x9d,0xcb,0xf9,0xbd,0x2e,0xd9};
    const bool is_v2 = version == 0x6b3343cf;
    const uint8_t* salt = is_v2 ? v2_salt : v1_salt;
    const size_t dcid_length = payload[5];
    size_t offset = 6;
    if (dcid_length > length - offset) return std::nullopt;
    const uint8_t* dcid = payload + offset; offset += dcid_length;
    if (offset >= length) return std::nullopt;
    const size_t scid_length = payload[offset++];
    if (scid_length > length - offset) return std::nullopt;
    offset += scid_length;
    bool ok = true;
    const uint64_t token_length = readQuicVarInt(payload, length, offset, ok);
    if (!ok || token_length > length - offset) return std::nullopt;
    offset += static_cast<size_t>(token_length);
    const size_t length_field_offset = offset;
    const uint64_t packet_length = readQuicVarInt(payload, length, offset, ok);
    if (!ok || packet_length > length - offset || packet_length < 17 || offset + 4 + 16 > length) return std::nullopt;
    const size_t packet_number_offset = offset;
    const size_t sample_offset = packet_number_offset + 4;
    if (sample_offset + 16 > length) return std::nullopt;

    uint8_t initial_secret[32], client_secret[32], key[16], iv[12], hp[16];
    if (!hkdfExtract(salt, 20, dcid, dcid_length, initial_secret) ||
        !hkdfExpandLabel(initial_secret, sizeof(initial_secret), "client in", client_secret, sizeof(client_secret)) ||
        !hkdfExpandLabel(client_secret, sizeof(client_secret), is_v2 ? "quicv2 key" : "quic key", key, sizeof(key)) ||
        !hkdfExpandLabel(client_secret, sizeof(client_secret), is_v2 ? "quicv2 iv" : "quic iv", iv, sizeof(iv)) ||
        !hkdfExpandLabel(client_secret, sizeof(client_secret), is_v2 ? "quicv2 hp" : "quic hp", hp, sizeof(hp))) return std::nullopt;

    EVP_CIPHER_CTX* hp_ctx = EVP_CIPHER_CTX_new();
    if (!hp_ctx) return std::nullopt;
    uint8_t mask[16]; int produced = 0;
    bool hp_ok = EVP_EncryptInit_ex(hp_ctx, EVP_aes_128_ecb(), nullptr, hp, nullptr) == 1 &&
        EVP_CIPHER_CTX_set_padding(hp_ctx, 0) == 1 &&
        EVP_EncryptUpdate(hp_ctx, mask, &produced, payload + sample_offset, 16) == 1;
    EVP_CIPHER_CTX_free(hp_ctx);
    if (!hp_ok) return std::nullopt;

    const size_t pn_length = ((payload[0] ^ (mask[0] & 0x0f)) & 0x03) + 1;
    if (pn_length > packet_length || packet_number_offset + pn_length + 16 > length) return std::nullopt;
    std::vector<uint8_t> aad(payload, payload + packet_number_offset + pn_length);
    aad[0] ^= mask[0] & 0x0f;
    uint64_t packet_number = 0;
    for (size_t i = 0; i < pn_length; ++i) { aad[packet_number_offset + i] ^= mask[i + 1]; packet_number = (packet_number << 8) | aad[packet_number_offset + i]; }
    (void)length_field_offset;
    for (size_t i = 0; i < sizeof(iv); ++i) iv[i] ^= static_cast<uint8_t>(packet_number >> (8 * (sizeof(iv) - 1 - i)));
    const size_t ciphertext_length = static_cast<size_t>(packet_length) - pn_length;
    const uint8_t* ciphertext = payload + packet_number_offset + pn_length;
    std::vector<uint8_t> plaintext(ciphertext_length);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::nullopt;
    int out_length = 0, final_length = 0;
    bool decrypt_ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) == 1 &&
        EVP_DecryptUpdate(ctx, nullptr, &out_length, aad.data(), static_cast<int>(aad.size())) == 1 &&
        EVP_DecryptUpdate(ctx, plaintext.data(), &out_length, ciphertext, static_cast<int>(ciphertext_length - 16)) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(ciphertext + ciphertext_length - 16)) == 1 &&
        EVP_DecryptFinal_ex(ctx, plaintext.data() + out_length, &final_length) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!decrypt_ok) return std::nullopt;
    return sniFromQuicCrypto(plaintext.data(), static_cast<size_t>(out_length + final_length));
}

} // namespace DPI
