#pragma once

#include <boost/asio.hpp>
#include <openssl/evp.h>
#include "../../Client/nlohmann/json.hpp"

#include <iostream>
#include <bitset>

namespace minec
{
    struct MSauth
    {
        std::string access_token{};
        unsigned long int expires_in = 0;
        std::string refresh_token{};

        MSauth() = default;
        MSauth(std::string access_token, unsigned long int expire, std::string refresh_token);

        void save();
        static MSauth load(bool& error);
    };
    struct Xauth
    {
        std::string token{};
        std::string uhs{};
    };

    struct RSA_encryption_keys
    {
        RSA* private_key;
        std::string public_key;
        std::string public_key_signature;
    };

    class profile_cosmetics
    {
    public:
        std::string id;
        bool active;
        std::string url;

        profile_cosmetics(const nlohmann::json& source);
    };
    class cape_info: public profile_cosmetics
    {
    public:
        std::string alias;
        cape_info(const nlohmann::json& source);
    };
    struct MCprofile
    {
        std::string username;
        std::string uuid;

        std::vector<profile_cosmetics> skins;
        std::vector<cape_info> capes;

        profile_cosmetics* active_skin;
        cape_info* active_cape;

        MCprofile(const nlohmann::json& source);

        void print() const;
    };

    class sha1
    {
    private:
        const EVP_MD *md;
        EVP_MD_CTX *mdctx;

        unsigned char md_value[20]{};
        unsigned int md_len{};
    public:
        sha1();
        void update(const std::vector<uint8_t>& input);
        std::string finalize();
    };

    class aes_encrypter
    {
    public:
        EVP_CIPHER_CTX* encryption_context = nullptr;
        EVP_CIPHER_CTX* decryption_context = nullptr;

        unsigned int blocksize = 0;
    public:
        void init(const std::vector<uint8_t>& pub_key,
            const std::vector<uint8_t>& v_token, const std::vector<uint8_t>& raw_shared_secret,
            std::vector<uint8_t>& encrypted_shared_secret, std::vector<uint8_t>& encrypted_vtoken);

        std::vector<uint8_t> encrypt(const std::vector<uint8_t>& input);
        std::vector<uint8_t> decrypt(const std::vector<uint8_t>& input);
    };

    class packet_buffer
    {
    private:
        void write(uint8_t val, size_t& where, bool insert);
    public:
        std::vector<uint8_t> buffer;
        size_t pointer = 0;

        void write_some(boost::asio::ip::tcp::socket& socket, boost::system::error_code& ec);
        void prep_and_send(boost::asio::ip::tcp::socket& socket, boost::system::error_code& ec);

        void finalize();

        void write_var_int(unsigned int value, size_t where = -1);

        void write_byte_arr(const std::vector<uint8_t>& arr, size_t where = -1);
        void write_string(const std::string& str, size_t where = -1);

        template <typename T>
        void write_number(std::enable_if<true, T>::type value, size_t where = -1)
        {
            size_t icpy = where;
            for (int i = sizeof(T); i > 0; --i)
            {
                uint8_t current = value >> ((sizeof(T)-1)*8);
                value = value << 8;

                write(current, icpy, where != -1);
            }
        }

        // expects uuid to be 32-char long HEX-number f. e. "069a79f444e94726a5befca90e38aaf5"
        void write_uuid(const std::string& uuid, size_t where = -1);

        unsigned int read_var_int(bool* success = nullptr, uint8_t* size = nullptr);

        std::vector<uint8_t> read_byte_arr();
        std::string read_string();

        static packet_buffer receive(boost::asio::ip::tcp::socket& socket, boost::system::error_code& ec, bool encrypted = true, aes_encrypter* that_thing = nullptr);

        packet_buffer() = default;
        packet_buffer(unsigned int packet_id);
    };

    std::string send_web_request(const std::string& host, const std::string& request, int& error_code);
    std::string generate_get_request(const std::string& host, const std::string& endpoint, const std::string& authorization);
    std::string generate_post_request(const std::string& host, const std::string& endpoint,
        const std::string& content_type, const std::string& data, const std::string& accept = "*/*", const std::string& authorization = "");

    MSauth ms_auth_device_flow(const std::string& app_id = "88650e7e-efee-4857-b9a9-cf580a00ef43");
    MSauth ms_refresh_auth(const MSauth& old_tokens, const std::string& app_id = "88650e7e-efee-4857-b9a9-cf580a00ef43");

    Xauth xbl_authentificate(const MSauth& ms_tokens);
    Xauth xsts_authentificate(const Xauth& xbl_token);
    std::string mc_authentificate(const Xauth& xsts_token);

    RSA_encryption_keys certificate(const std::string& mc_access_token);

    std::string authentificate(const std::string& app_id = "88650e7e-efee-4857-b9a9-cf580a00ef43");

    MCprofile get_profile_info(const std::string& mc_access_token);
}