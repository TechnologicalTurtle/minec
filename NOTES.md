# DA LINKS
- [packet format](https://minecraft.wiki/w/Java_Edition_protocol/Packets#Packet_format)
- [list of packets](https://minecraft.wiki/w/Java_Edition_protocol/Packets#List_of_packets)
- [login yapping](https://minecraft.wiki/w/Java_Edition_protocol/Packets#Login_2)
- [botcraft auth](https://github.com/adepierre/Botcraft/blob/703361dde8fa65632595ea2cafefcbd714c94c1d/botcraft/src/Network/Authentifier.cpp#L599)
- [MS_AUTH](https://github.com/maxsupermanhd/go-mc-ms-auth/blob/master/auth.go#L85)
- [AAAAAA](https://minecraft.wiki/w/Java_Edition_protocol/Encryption)

```c++
int main()
{
std::string host = "jaroska.cz";
std::string port_num = "20";

    // create an resolver
    asio::io_service ios;
    asio::ip::tcp::resolver resolver(ios);

    // Used to store information about error that happens
    // during the resolution process.
    system::error_code ec;

    // Step 5.
    asio::ip::tcp::resolver::iterator itr =
        resolver.resolve(host, port_num, ec);
    asio::ip::tcp::resolver::iterator end;

    // Handling errors if any.
    if (ec) {
        // Failed to resolve the DNS name. Breaking execution.
        std::cout << "Failed to resolve a DNS name."
          << "Error code = " << ec.value()
          << ". Message = " << ec.message();

        return ec.value();
    }

    if (asio::ip::v6_only()) std::cerr << "IPv6 not supported yet!";

    for (int i = 1; itr != end; ++itr, ++i)
        std::cout << "hostname #" << i << ": " << itr->host_name() << ">>" << itr->endpoint().address() << '\n';

    return 0;
}
```

```c++
#include <boost/asio.hpp>

#include <iostream>
#include <thread>

#include <bitset>

using namespace boost;

// Overload << for output
std::ostream &operator<<(std::ostream& out, const std::vector<unsigned char>&v)
{
out << '[';
for (int i = 0; i < v.size()-1; ++i) out << (int)v[i] << ", ";
out << (int)v[v.size()-1];
out << ']';
return out;
}

void writeVarInt(unsigned int value, std::vector<unsigned char>& buffer)
{
if (value == 0) buffer.push_back(0);
for (int i = 0; i < 5 && value > 0; ++i)
{
// get last 7 bits of value
unsigned char current = value & 127;
// scrape them from value
value >>= 7;
// add non-end flag
if (value > 0)
current |= 128;
buffer.push_back(current);
}
}
unsigned int readVarInt(unsigned char*& source)
{
unsigned int value = 0;
int i = 0;
for (; i < 5; ++i)
{
// load i-th byte of source
unsigned char current = source[i];
// add that byte (without end flag) to beginning of value
value |= (current & 127) << 7*i;
if (!(current >> 7))
break;
}
source = source + i + 1;
return value;
}

void writeByteArray(std::vector<unsigned char>& array, std::vector<unsigned char>& buffer)
{
// foo-len prefix
writeVarInt(array.size(), buffer);

    // copy 'array' to the 'buffer'
    for (const auto c : array) buffer.push_back(c);
}
std::vector<unsigned char> readByteArray(unsigned char*& source)
{
unsigned int len = readVarInt(source);

    std::vector<unsigned char> ret;
    ret.reserve(len);
    for (int i = 0; i < len; ++i)
    {
        ret.push_back(source[i]);
    }

    source = source + len;
    return ret;
}
void writeString(std::string value, std::vector<unsigned char>& buffer)
{
std::vector<unsigned char> serv(value.begin(), value.end());
writeByteArray(serv, buffer);
}
std::string readString(unsigned char*& source)
{
std::vector<unsigned char> arr = readByteArray(source);
return {arr.begin(), arr.end()};
}

void write_uuid(std::vector<unsigned char>& buffer, const std::string& uuid)
{
    auto get_char_val = [](char in)-> __int8_t
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

        throw std::invalid_argument("got unexpected character outside of {0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,A,B,C,D,E,F}");
    };

    for (int i = 0; i < uuid.size(); i+=2)
    {
        std::cerr << uuid[i] << uuid[i+1] << '\n';
        buffer.push_back(get_char_val(uuid[i])*16 + get_char_val(uuid[i+1]));
    }
}

void generateHeader(unsigned int id, std::vector<unsigned char>& buffer)
{
std::vector<unsigned char> packet_id;
writeVarInt(id, packet_id);
std::vector<unsigned char> size;
writeVarInt(buffer.size() + packet_id.size(), size);
std::cerr << buffer.size() + packet_id.size() << '\n';

    buffer.insert(buffer.begin(), packet_id.begin(), packet_id.end());
    buffer.insert(buffer.begin(), size.begin(), size.end());
}

int main() {
system::error_code ec;

    asio::io_context context;

    asio::io_context::work idle_work(context);
    std::thread run_context([&](){  context.run();  });

    asio::ip::tcp::endpoint endpoint(asio::ip::make_address("172.65.197.160", ec), 25565);
    std::cout << "Skibidi >> " << ec.message() << '\n';

    asio::ip::tcp::socket socket(context);
    socket.connect(endpoint, ec);
    std::cerr << ec.message() << '\n';

    if (ec)
    {
        std::cout << "BAD\n";
        return ec.value();
    }

    std::string server = "mc.hypixel.net";
    std::vector<unsigned char> packet1;
    writeVarInt(776, packet1); // version
    writeString(server, packet1);
    packet1.push_back(99); // port p1 01100011
    packet1.push_back(221);// port p2 11011101
    writeVarInt(2, packet1); // intention LOGIN
    generateHeader(0x00, packet1);

    std::string username = "fanda135";
    std::vector<unsigned char> packet2;
    writeString(username, packet2);
    packet2.push_back(0b01001111);
    packet2.push_back(0b11101101);
    packet2.push_back(0b10000110);
    packet2.push_back(0b10001100);
    packet2.push_back(0b01101000);
    packet2.push_back(0b00001100);
    packet2.push_back(0b01001111);
    packet2.push_back(0b11000010);
    packet2.push_back(0b10000000);
    packet2.push_back(0b00000110);
    packet2.push_back(0b11100001);
    packet2.push_back(0b00101110);
    packet2.push_back(0b01010111);
    packet2.push_back(0b01111100);
    packet2.push_back(0b01101000);
    packet2.push_back(0b10001101);
    generateHeader(0, packet2);

    socket.write_some(asio::buffer(packet1.data(), packet1.size()), ec);
    socket.write_some(asio::buffer(packet2.data(), packet2.size()), ec);

    std::this_thread::sleep_for(std::chrono::operator ""ms(10000));

    std::vector<unsigned char> vBuffer(socket.available());
    socket.read_some(asio::buffer(vBuffer.data(), vBuffer.size()), ec);
    std::cerr << ec.message() << '\n';

    std::cout << "RESPONSE: ";
    for (unsigned char c : vBuffer) std::cout << std::bitset<8>(c);
    std::cout << "" << std::endl;

    unsigned char* it = vBuffer.data();
    std::cout << "PACKET SIZE: " << readVarInt(it) << '\n';
    std::cout << "PACKET ID: "   << readVarInt(it) << '\n';
    std::cout << "SERVER ID: " << readByteArray(it) << '\n';
    std::cout << "PUBLIC KEY: " << readByteArray(it) << '\n';
    std::cout << "VTOKEN: " << readByteArray(it) << '\n';
    std::cout << "AUTH?: " << std::boolalpha << (readVarInt(it)==1) << '\n';

    return 0;
}
```
```c++
#include <boost/algorithm/string.hpp>

#include <iostream>
#include <fstream>

#include "include/minec.hpp"
#include "nlohmann/json.hpp"

#include <string>

using namespace boost;
using json = nlohmann::json;

const std::string app_id = "88650e7e-efee-4857-b9a9-cf580a00ef43";

int main()
{
    //std::string mc_access_token = minec::authentificate();
    //std::cerr << "MC_ACCESS_TOKEN>>" << mc_access_token << '\n';
    std::string mc_access_token = "";
    minec::MCprofile plr = minec::get_profile_info(mc_access_token);

    std::cout <<
        "-PLAYER FETCHED-"
        "\n  nick: " + plr.username +
        "\n  uuid: " + plr.uuid +
        "\n  skin: " + plr.active_skin->url +
        "\n  cape: " +(plr.active_cape!=nullptr?plr.active_cape->alias:"none")+'\n';

    return 0;
}
```
