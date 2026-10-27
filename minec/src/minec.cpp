#include "include/minec.hpp"

#include <bitset>
#include <string>
#include <format>
#include <fstream>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/aes.h>

#include <boost/asio/ssl.hpp>

#include <iostream>

using namespace boost;
using json = nlohmann::json;

static size_t get_stream_size(std::stringstream& ss)
{
    ss.seekg(0, std::ios::end);
    size_t size = ss.tellg();
    ss.seekg(0, std::ios::beg);

    return size;
}

namespace minec
{
    MSauth::MSauth(std::string access_token, unsigned long int expire, std::string refresh_token)
            :access_token(std::move(access_token)), expires_in(time(nullptr) + expire), refresh_token(std::move(refresh_token))
    {}

    void MSauth::save()
    {
        json save = {
            {"access_token", access_token},
            {"expires_in", expires_in},
            {"refresh_token", refresh_token}
        };

        std::ofstream file("minec_auth_cache.txt");

        file << save.dump();
        file.close();
    }

    // NEEDS REWORK
    MSauth MSauth::load(bool& error)
    {
        std::ifstream file("minec_auth_cache.txt");
        json loaded = json::parse(file);

        MSauth result = {"", 0, ""};
        try
        {
            result = {
                loaded["access_token"].get<std::string>(),
                0,
                loaded["refresh_token"].get<std::string>()
            };
            result.expires_in = loaded["expires_in"];
            error = false;
        }
        catch (std::exception&)
        {
            std::cerr << "Couldn't load ms auth cache file...ms authentification needed\n";
            error = true;
        }

        return result;
    }

    sha1::sha1()
    {
        md = EVP_get_digestbyname("SHA1");
        mdctx = EVP_MD_CTX_new();

        EVP_DigestInit_ex2(mdctx, md, nullptr);
    }
    void sha1::update(const std::vector<uint8_t>& input)
    {
        EVP_DigestUpdate(mdctx, input.data(), input.size());
    }
    std::string sha1::finalize()
    {
        EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        EVP_MD_CTX_free(mdctx);

        std::string result;
        bool signed_hash = false;
        // sign
        if (md_value[19] & 1)
        {
            for (int i = 0; i < md_len; i++) md_value[i] = ~md_value[i];
            signed_hash = true;
        }

        // convert to string
        std::stringstream ss;
        for (unsigned char byte : md_value) {
            ss << std::format("{:02x}", byte);
        }
        ss >> result;
        if (signed_hash) result.insert(result.begin(), '-');

        return result;
    }

    void aes_encrypter::init(const std::vector<uint8_t>& pub_key,
        const std::vector<uint8_t>& v_token, const std::vector<uint8_t>& raw_shared_secret,
        std::vector<uint8_t>& encrypted_shared_secret, std::vector<uint8_t>& encrypted_vtoken)
    {
        const unsigned char* pub_key_ptr = pub_key.data();

        RSA* rsa = d2i_RSA_PUBKEY(nullptr, &pub_key_ptr, static_cast<long>(pub_key.size()));

        int rsa_size = RSA_size(rsa);

        encrypted_shared_secret.resize(rsa_size);
        RSA_public_encrypt(16, raw_shared_secret.data(), encrypted_shared_secret.data(), rsa, RSA_PKCS1_PADDING);

        encrypted_vtoken.resize(rsa_size);
        RSA_public_encrypt(static_cast<int>(v_token.size()), v_token.data(), encrypted_vtoken.data(), rsa, RSA_PKCS1_PADDING);

        RSA_free(rsa);


        if (encryption_context != nullptr)
        {
            EVP_CIPHER_CTX_free(encryption_context);
            encryption_context = nullptr;
        }
        encryption_context = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(encryption_context, EVP_aes_128_cfb8(), nullptr, raw_shared_secret.data(), raw_shared_secret.data());

        if (decryption_context != nullptr)
        {
            EVP_CIPHER_CTX_free(decryption_context);
            decryption_context = nullptr;
        }
        decryption_context = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(decryption_context, EVP_aes_128_cfb8(), nullptr, raw_shared_secret.data(), raw_shared_secret.data());

        blocksize = EVP_CIPHER_block_size(EVP_aes_128_cfb8());
    }

    std::vector<uint8_t> aes_encrypter::encrypt(const std::vector<uint8_t>& input)
    {
        std::vector<uint8_t> output;
        int size = 0;

        output.resize(input.size() + blocksize);
        EVP_EncryptUpdate(encryption_context, output.data(), &size, input.data(), static_cast<int>(input.size()));
        output.resize(size);

        return output;
    }
    std::vector<uint8_t> aes_encrypter::decrypt(const std::vector<uint8_t>& input)
    {
        std::vector<uint8_t> output;
        int size = 0;

        output.resize(input.size() + blocksize);
        EVP_DecryptUpdate(decryption_context, output.data(), &size, input.data(), static_cast<int>(input.size()));
        output.resize(size);

        return output;
    }

    profile_cosmetics::profile_cosmetics(const nlohmann::json& source)
        : id(source["id"].get<std::string>()), active(source["state"].get<std::string>()=="ACTIVE"),
          url(source["url"].get<std::string>())
    {}
    cape_info::cape_info(const nlohmann::json& source)
        :profile_cosmetics(source), alias(source["alias"].get<std::string>())
    {}

    MCprofile::MCprofile(const nlohmann::json& source)
        : username(source["name"].get<std::string>()), uuid(source["id"].get<std::string>())
    {
        for (const json& skin : source["skins"])
        {
            profile_cosmetics& skin_ref = skins.emplace_back(skin);
            if (skin_ref.active) active_skin = &skin_ref;
        }

        for (const json& cape : source["capes"])
        {
            cape_info& cape_ref = capes.emplace_back(cape);
            if (cape_ref.active) active_cape = &cape_ref;
        }
    }
    void MCprofile::print() const
    {
        std::cout <<
            "-PLAYER FETCHED-"
            "\n  nick: " + username +
            "\n  uuid: " + uuid +
            "\n  skin: " + active_skin->url +
            "\n  cape: " +(active_cape!=nullptr?active_cape->alias:"none")+'\n';
    }

    void packet_buffer::write(uint8_t val, size_t& where, bool insert)
    {
        if (insert)
        {
            buffer.insert(buffer.begin()+where, val);
            where++;
        }
        else
            buffer.push_back(val);
    }

    void packet_buffer::write_some(asio::ip::tcp::socket& socket, system::error_code& ec)
    {
        socket.write_some(asio::buffer(buffer.data(), buffer.size()), ec);
    }
    void packet_buffer::prep_and_send(asio::ip::tcp::socket& socket, system::error_code& ec)
    {
        finalize();
        write_some(socket, ec);
    }

    void packet_buffer::finalize()
    {
        write_var_int(buffer.size(), 0);
    }

    void packet_buffer::write_var_int(unsigned int value, size_t where)
    {
        const bool insert = where != -1;
        if (value == 0) write(0, where, insert);
        for (int i = 0; i < 5 && value > 0; ++i)
        {
            // get last 7 bits of value
            uint8_t current = value & 127;
            // scrape them from value
            value >>= 7;
            // add non-end flag
            if (value > 0)
                current |= 128;
            write(current, where, insert);
        }
    }

    void packet_buffer::write_byte_arr(const std::vector<uint8_t>& arr, size_t where)
    {
        const bool insert = where != -1;
        // foo-len prefix
        write_var_int(arr.size(), where);

        // copy 'arr' to the 'buffer'
        for (const auto c : arr) write(c, where, insert);
    }
    void packet_buffer::write_string(const std::string& str, size_t where)
    {
        std::vector<unsigned char> serv(str.begin(), str.end());
        write_byte_arr(serv, where);
    }

    void packet_buffer::write_uuid(const std::string& uuid, size_t where)
    {
        const bool insert = where != -1;
        auto get_char_val = [](char in)
        {
            //        0           9
            if (in >= 48 && in <= 57)
                return in - 48;
            //        a           f
            if (in >= 97 && in <= 102)
                return in - 87;
            //        A           F
            if (in >= 65 && in <= 70)
                return in - 55;
            throw std::invalid_argument(std::string("got unexpected character '") + in + "' outside of {0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,A,B,C,D,E,F}");
        };

        for (int i = 0; i < uuid.size(); i+=2) write(get_char_val(uuid[i])*16 + get_char_val(uuid[i+1]), where, insert);
    }

    unsigned int packet_buffer::read_var_int(bool* success, uint8_t* size)
    {
        unsigned int value = 0;
        int i = 0;
        for (; i < 5; ++i)
        {
            if (i >= buffer.size())
            {
                if (success != nullptr)
                    *success = false;
                else
                    throw std::out_of_range("var_int didn't end (at least before end of buffer && no 'success' variable was set)");
                return -1;
            }

            // load i-th byte of source
            const uint8_t current = buffer[pointer + i];

            // add that byte (without end flag) to beginning of value
            value |= (current & 127) << 7*i;
            if (!(current >> 7))
                break;
        }
        if (i >= 5)
        {
            if (success != nullptr)
                *success = false;
            else
                throw std::out_of_range("var_int was probably longer than maximum of 5 bytes (and no 'success' variable was set)");
            return -1;
        }
        if (size != nullptr) *size = i + 1;
        if (success != nullptr) *success = true;
        pointer = pointer + i + 1;
        return value;
    }

    std::vector<uint8_t> packet_buffer::read_byte_arr()
    {
        unsigned int len = read_var_int();

        std::vector<unsigned char> ret;
        ret.reserve(len);
        for (int i = 0; i < len; ++i)
        {
            if (i >= buffer.size()) throw std::out_of_range("byte array reportedly out of range");
            ret.push_back(buffer[pointer + i]);
        }

        pointer = pointer + len;
        return ret;
    }
    std::string packet_buffer::read_string()
    {
        std::vector<unsigned char> arr = read_byte_arr();
        return {arr.begin(), arr.end()};
    }

    packet_buffer packet_buffer::receive(asio::ip::tcp::socket& socket, system::error_code& ec, bool encrypted, aes_encrypter* that_thing)
    {
        packet_buffer response;
        bool success = false; size_t expected_sz = -1;
        std::vector<uint8_t> new_byte(1);
        while (!success)
        {
            asio::read(socket, asio::buffer(&new_byte[new_byte.size()-1], 1), asio::transfer_exactly(1), ec);

            if (encrypted)
                response.buffer.push_back(that_thing->decrypt(new_byte)[0]);
            else
                response.buffer.push_back(new_byte[0]);

            expected_sz = response.read_var_int(&success);
            response.pointer = 0;
        }
        std::cerr << "EXPECTED SIZE: " << expected_sz << '\n';
        response.buffer.resize(expected_sz);
        asio::read(socket, asio::buffer(response.buffer.data(), response.buffer.size()), asio::transfer_exactly(expected_sz), ec);

        if (encrypted)
            response.buffer = that_thing->decrypt(response.buffer);

        return response;
    }

    packet_buffer::packet_buffer(unsigned int packet_id)
    {
        write_var_int(packet_id);
    }

    std::string send_web_request(const std::string& host, const std::string& request, int& error_code)
    {
        system::error_code ec;
        asio::io_context io_context;

        asio::ip::tcp::resolver resolver(io_context);
        asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(host, "https");

        asio::ssl::context ctx(asio::ssl::context::sslv23);
        ctx.set_default_verify_paths();
        ctx.set_options(asio::ssl::context::default_workarounds | asio::ssl::context::verify_none);

        asio::ssl::stream<asio::ip::tcp::socket> socket(io_context, ctx);
        socket.set_verify_mode(asio::ssl::verify_none);
        socket.set_verify_callback([](bool, asio::ssl::verify_context&) { return true; });
        SSL_set_tlsext_host_name(socket.native_handle(), host.c_str());
        asio::connect(socket.lowest_layer(), endpoints);
        socket.handshake(asio::ssl::stream<asio::ip::tcp::socket>::client);
        socket.lowest_layer().set_option(asio::ip::tcp::no_delay(true));

        asio::write(socket, asio::buffer(request));

        asio::streambuf response;
        asio::read_until(socket, response, "\r\n\r\n");

        std::istream header(&response);
        std::string http_version;
        header >> http_version;
        header >> error_code;

        const std::string transfer_encoding_head = "Transfer-Encoding: ";
        bool chunked_encoding = false;

        const std::string content_length_head = "Content-Length: ";
        unsigned int expected_length = 0;
        std::string line;
        while (std::getline(header, line) && line != "\r")
        {
            if (line.back() == '\r') line.pop_back();

            if (expected_length == 0 && line.substr(0, content_length_head.size()) == content_length_head)
                expected_length = std::stoi(line.substr(content_length_head.size()));

            if (line.substr(0, transfer_encoding_head.size()) == transfer_encoding_head)
                chunked_encoding = true;
        }

        std::stringstream data;
        if (chunked_encoding)
        {
            std::stringstream helper;
            while (asio::read(socket, response, asio::transfer_at_least(1), ec))
            {
                helper << &response;
            }
            while (true)
            {
                getline(helper, line, '\r');
                if (line == "\n0") break;
                getline(helper, line, '\r');
                data << line;
            }
        }
        else
        {
            while (get_stream_size(data) < expected_length)
            {
                asio::read(socket, response, asio::transfer_at_least(1), ec);
                data << &response;
            }
        }

        return data.str();
    }

    std::string generate_get_request(const std::string& host, const std::string& endpoint, const std::string& authorization)
    {
        return
            "GET " + endpoint + " HTTP/1.1 \r\n"
            "Host: " + host + "\r\n"+
            (!authorization.empty() ?
                "Authorization: " + authorization + "\r\n"
                :
                ""
            )+
            "User-Agent: C/1.0\r\n"
            "Connection: close"
            "\r\n\r\n";
    }
    std::string generate_post_request(const std::string& host, const std::string& endpoint,
        const std::string& content_type, const std::string& data, const std::string& accept, const std::string& authorization)
    {
        return
            "POST " + endpoint + " HTTP/1.1 \r\n"
            "Host: " + host + "\r\n"
            "User-Agent: C/1.0\r\n"
            "Content-Type: "+ content_type + "\r\n"
            "Accept: " + accept + "\r\n"
            "Content-Length: " + std::to_string(data.length()) + "\r\n"
            "Connection: close"+
            (!authorization.empty() ?
                "\r\nAuthorization: " + authorization
                :
                ""
            )+
            "\r\n\r\n" +
            data;
    }

    MSauth ms_auth_device_flow(const std::string& app_id)
    {
        int error_code;

        const std::string auth_data = std::string("client_id=") + app_id + "&scope=XboxLive.signin%20offline_access";

        std::string raw_auth_request = generate_post_request("login.microsoftonline.com", "/consumers/oauth2/v2.0/devicecode",
                "application/x-www-form-urlencoded", auth_data);

        json auth_response = json::parse(send_web_request("login.microsoftonline.com", raw_auth_request, error_code));

        std::cerr << auth_response["message"] << '\n';

        const long long int pool_interval = auth_response["interval"];

        std::string device_id = auth_response["device_code"];
        const std::string check_data =
                    "client_id=" + app_id +
                    "&scope=XboxLive.signin%20offline_access" +
                    "&grant_type=urn:ietf:params:oauth:grant-type:device_code" +
                    "&device_code=" + device_id;

        std::string raw_check_request = generate_post_request("login.microsoftonline.com", "/consumers/oauth2/v2.0/token",
                   "application/x-www-form-urlencoded", check_data);

        MSauth ms_auth_tokens;
        while (true)
        {
            std::this_thread::sleep_for(std::chrono::seconds(pool_interval + 1));

            json response = json::parse(send_web_request("login.microsoftonline.com", raw_check_request, error_code));
            if (error_code == 400)
            {
                std::cerr << "HTTP ERROR CODE:" << error_code << '\n';
                if (!response.contains("error"))
                {
                    std::cerr << "GOT WEIRD JSON: " << response.dump(2) << '\n';
                }
                std::string error = response["error"];
                if (error == "authorization_pending") {
                    continue;
                }
                if (error == "authorization_declined") {
                    std::cerr << "user declined authorization\n";
                return {};
                }
                if (error == "expired_token") {
                    std::cerr << "user didn't authorize in time\n";
                return {};
                }
                if (error == "invalid_grant") {
                    std::cerr << "while pooling token got invalid_grant error: " << response["error_description"];
                return {};
                }
            }
            else if (error_code == 200)
            {
                std::cerr << "Microslop authentification succeeded!\n";
                std::cerr << response.dump(2) << '\n';

                return {response["access_token"], response["expires_in"], response["refresh_token"]};
                break;
            }
            else
            {
                std::cerr << "Response from server wasn't 200 or 400? :\n" << response.dump(2) << '\n';
                return {};
            }
        }
    }
    MSauth ms_refresh_auth(const MSauth& old_tokens, const std::string& app_id)
    {
        if (old_tokens.expires_in > time(nullptr))
        {
            std::cerr << "tokens won't be refreshed as they are fresh enough (" << old_tokens.expires_in << '>' << time(nullptr) << ")\n";
            return old_tokens;
        }

        int error_code;

        std::string ms_data =
            "client_id=" + app_id +
            "&refresh_token=" + old_tokens.refresh_token +
            "&grant_type=refresh_token"
            "&redirect_uri=https://login.microsoftonline.com/common/oauth2/nativeclient";

        std::string raw_ms_data = generate_post_request("login.live.com", "/oauth20_token.srf",
            "application/x-www-form-urlencoded", ms_data);

        std::string MSresponse = send_web_request("login.live.com", raw_ms_data, error_code);

        json response = json::parse(MSresponse);

        if (error_code != 200)
        {
            std::cerr << "Got " << error_code << " instead of 200 status code!\n";
            std::cerr << response.dump(2) << '\n';
            return {};
        }

        MSauth ms_token{response["access_token"], response["expires_in"], response["refresh_token"]};
        ms_token.save();
        std::cerr << "Microslop access token refreshing succeeded.\n";
        return ms_token;
    }

    Xauth xbl_authentificate(const MSauth& ms_tokens)
    {
        int error_code;

        json xbl_json_data =
        {
            {"Properties", {{"AuthMethod", "RPS"},{"SiteName", "user.auth.xboxlive.com"},{"RpsTicket", "d=" + ms_tokens.access_token}}},
            {"RelyingParty", "http://auth.xboxlive.com"},
            {"TokenType", "JWT"}
        };
        std::string xbl_post_req = generate_post_request("user.auth.xboxlive.com", "/user/authenticate",
            "application/json", xbl_json_data.dump(), "application/json");

        json xbl_token_json = json::parse(send_web_request("user.auth.xboxlive.com", xbl_post_req, error_code));

        if (error_code != 200)
        {
            std::cerr << "Got " << error_code << " instead of 200 status code!\n";
            std::cerr << xbl_token_json.dump(2) << '\n';
            return {};
        }

        std::cerr << "Xbox live authentification succeeded.\n";
        return {xbl_token_json["Token"].get<std::string>(), xbl_token_json["DisplayClaims"]["xui"][0]["uhs"].get<std::string>()};
    }

    Xauth xsts_authentificate(const Xauth& xbl_token)
    {
        int error_code;

        json xsts_in_json =
        {
            {
                "Properties", {
                    {"SandboxId", "RETAIL"},
                    {"UserTokens", {  xbl_token.token  }}
                },
            },
            {"RelyingParty", "rp://api.minecraftservices.com/"},
            {"TokenType", "JWT"}
        };
        std::string xsts_in_raw = generate_post_request("xsts.auth.xboxlive.com", "/xsts/authorize",
            "application/json", xsts_in_json.dump(), "application/json");

        json xsts_response = json::parse(send_web_request("xsts.auth.xboxlive.com", xsts_in_raw, error_code));

        if (error_code != 200)
        {
            std::cerr << "XTLS ERROR!\n";
            std::cerr << xsts_response.dump(2) << '\n';
            switch (xsts_response["XErr"].get<unsigned long long>())
            {
                case 2148916227:
                    std::cerr << "> Account banned from Xbox!\n";
                    return {};
                case 2148916233:
                    std::cerr << "> Account doesn't have an Xbox account; create one to unerror this error!\n";
                    return {};
                case 2148916235:
                    std::cerr << "> Account not available in country of origin of this account!\n";
                    return {};
                case 2148916236:
                case 2148916237:
                    std::cerr << "> Account needs adult verification on Xbox page. (South Korea)\n";
                    return {};
                case 2148916238:
                    std::cerr << "> The account is a child (<18) and cannot proceed unless the account is added to a Family by an adult.\n";
                    return {};
                case 2148916262:
                    std::cerr << "> TBD error\n";
                    return {};
                default:
                    std::cerr << "> UNKNOWN ERROR:\n> " << xsts_response.dump(2) << '\n';
                    return {};
            }
        }

        std::cerr << "XSTS authentification succeeded.\n";
        return {xsts_response["Token"].get<std::string>(), xsts_response["DisplayClaims"]["xui"][0]["uhs"].get<std::string>()};
    }

    std::string mc_authentificate(const Xauth& xsts_token)
    {
        int error_code;

        json mc_in_json = {{"identityToken", "XBL3.0 x=" + xsts_token.uhs + ';' + xsts_token.token}};
        std::string mc_in_raw = generate_post_request("api.minecraftservices.com", "/authentication/login_with_xbox",
            "application/json", mc_in_json.dump(), "application/json");

        json mc_result = json::parse(send_web_request("api.minecraftservices.com", mc_in_raw, error_code));

        if (error_code != 200)
        {
            std::cerr << "Got " << error_code << " instead of 200 status code!\n";
            std::cerr << mc_result.dump(2) << '\n';
            return "";
        }
        return mc_result["access_token"].get<std::string>();
    }

    RSA_encryption_keys certificate(const std::string& mc_access_token)
    {
        int error_code;

        std::string cert_in_raw = generate_post_request("api.minecraftservices.com", "/player/certificates",
            "application/json", "", "*/*", "Bearer " + mc_access_token);

        json cert_result = json::parse(send_web_request("api.minecraftservices.com", cert_in_raw, error_code));

        if (error_code != 200)
        {
            std::cerr << "Got " << error_code << " instead of 200 status code!\n";
            std::cerr << cert_result.dump(2) << '\n';
            return {};
        }

        BIO* keybio = BIO_new_mem_buf(cert_result["keyPair"]["privateKey"].get<std::string>().c_str(), -1);
        RSA* private_key = PEM_read_bio_RSAPrivateKey(keybio, &private_key, nullptr, nullptr);
        BIO_free(keybio);

        return {private_key, cert_result["keyPair"]["publicKey"].get<std::string>(), cert_result["publicKezSignatureV2"].get<std::string>()};
    }

    std::string authentificate(const std::string& app_id)
    {
        bool needs_auth;
        MSauth ms_token = ms_refresh_auth(MSauth::load(needs_auth));
        if (needs_auth) ms_token = ms_auth_device_flow(app_id);

        Xauth xbl_token = xbl_authentificate(ms_token);
        Xauth xsts_token = xsts_authentificate(xbl_token);

        return mc_authentificate(xsts_token);
    }

    MCprofile get_profile_info(const std::string& mc_access_token)
    {
        std::ifstream cache_file_in("minec_mcprof_cache.txt");
        if (cache_file_in.good())
        {
            std::string temp; getline(cache_file_in, temp);
            if (temp.empty()) std::cerr << "couldn't find MCprof cache file... gotta fetch the stuff now ;(\n";
            else if (std::stoul(temp) < time(nullptr)) std::cerr << "cache expired... gotta fetch the stuff again ;(\n";
            else
            {
                getline(cache_file_in, temp, '\0');
                json cache = json::parse(temp);
                if (!cache.contains("id") || !cache.contains("name")
                     || !cache.contains("skins") || !cache.contains("capes"))
                    std::cerr << "file probably malformed... gotta fetch the stuff again ;(\n";
                else
                {
                    std::cerr << "yaaay! found cached prof info!\n";
                    return {cache};
                }
            }
        }

        std::string raw_info_req = generate_get_request("api.minecraftservices.com", "/minecraft/profile", "Bearer " + mc_access_token);

        int error_code;
        std::string got = send_web_request("api.minecraftservices.com", raw_info_req, error_code);

        std::ofstream cache_file_out("minec_mcprof_cache.txt");
        cache_file_out << time(nullptr)+24*60*60 << got;
        cache_file_out.close();

        nlohmann::json response = nlohmann::json::parse(got);

        if (!response.contains("id") || !response.contains("name")
                     || !response.contains("skins") || !response.contains("capes")) {
            std::cerr << "access key probably expired... gotta fetch the program again ;(\n got (" << response.dump(2) << ")\n";
            throw std::exception();
        }

        return {response};
    }
}