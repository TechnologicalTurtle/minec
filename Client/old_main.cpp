#include <iostream>
#include <thread>
#include <random>
#include <bit>

#include <fstream>

#include <bitset>
#include <fstream>

#include <openssl/ssl.h>
#include <openssl/pem.h>

#include "old_include/minec.hpp"
#include "nlohmann/json.hpp"
using json = nlohmann::json;

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
std::ostream &operator<<(std::ostream& out, const minec::packet_buffer&v)
{
    for (const auto ch : v.buffer) out << ch;

    return out;
}
std::ostream &operator>>(std::ostream& out, const minec::packet_buffer&v)
{
    for (const auto ch : v.buffer) out << std::bitset<8>(ch) << ' ';

    return out;
}

std::ostream &operator<<(std::ostream& out, const minec::vec3i&v)
{
    out << v.x << ", " << v.y << ", " << v.x;
}

template <typename T>
void rev_memcpy(T* dest, uint8_t const* src, size_t n)
{
    for (size_t i = 0; i < n; ++i)
    {
        dest[n-i-1] = src[i];
    }
}
void reverse_intcpy(double* dst, const double* src, size_t n)
{
    size_t i;

    for (i=0; i < n; ++i)
        dst[n-1-i] = src[i];

}
void read_NBT(minec::packet_buffer& source, int padding = 1, uint8_t type = -1)
{
    if (type == static_cast<uint8_t>(-1))
        type = source.read_number<uint8_t>();
    bool named = type == 10;

    uint8_t val_type = -1;
    unsigned int len = 0;
    if (!named)
    {
        val_type = source.read_number<uint8_t>();
        len = source.read_number<unsigned int>();
    }
    if (len > 0 || named)
        std::cerr << '\n';

    std::string prefix;
    for (int i = 0; i < padding; ++i) prefix += "  ";

    while (named || (len > 0))
    {
        len--;

        if (named)
        {
            val_type = source.read_number<uint8_t>();
            if (named && val_type == 0) // TAG_End
            {
                std::cerr << prefix.substr(0, padding*2-2) << "TAG_End\n";
                return;
            }

            auto name_length = source.read_number<short>();
            std::string val_name(source.buffer.begin()+source.pointer, source.buffer.begin()+source.pointer+name_length);
            source.pointer += name_length;
            std::cerr << prefix << val_name << ':';
        }
        else std::cerr << prefix;
        switch (val_type)
        {
            case 1: // TAG_Byte
                std::cerr << (int)source.buffer[source.pointer];
                source.pointer++;
                break;
            case 2: // TAG_Short
                std::cerr << source.read_number<short>();
                break;
            case 3: // TAG_Int
                std::cerr << source.read_number<int>();
                break;
            case 4: // TAG_Long
                std::cerr << source.read_number<unsigned long long>();
                break;
            case 5: // TAG_Float
            {
                std::cerr << std::bit_cast<float>(source.read_number<uint32_t>());
                break;
            }
            case 6: // TAG_Double
            {
                std::cerr << std::bit_cast<double>(source.read_number<uint64_t>());
                break;
            }
            case 7: // TAG_ByteArray
            {
                auto len = source.read_number<unsigned int>();
                source.pointer += len;
                std::cerr << "BYTE ARR not implemented!";
                break;
            }
            case 8: // TAG_String
            {
                auto string_length = source.read_number<short>();
                std::string val(source.buffer.begin()+source.pointer, source.buffer.begin()+source.pointer+string_length);
                std::cerr << val;
                source.pointer += string_length;
                break;
            }
            case 9: // TAG_List
            case 10: // TAG_Compound
            {
                std::cerr << (val_type==10?"COMPOUND":"LIST");
                read_NBT(source, padding+1, val_type);
                break;
            }
            case 11: // TAG_Int_Array
            {
                auto len = source.read_number<unsigned int>();
                source.pointer += len;
                std::cerr << "INT ARR not implemented!";
                break;
            }
            case 12: // TAG_Long_Array
            {
                auto len = source.read_number<unsigned int>();
                source.pointer += len;
                std::cerr << "LONG ARR not implemented!";
                break;
            }
            default:
                std::cerr << "TAG " << (int)val_type << " doesn't exist!\n";
                throw std::invalid_argument("invalid tag!");
                break;
        }
        std::cerr << '\n';
    }
}

int main()
{
    system::error_code ec;
    asio::io_context context;

    asio::io_context::work idle_work(context);
    std::thread run_context([&](){  context.run();  });
    run_context.detach();

    asio::ip::tcp::endpoint endpoint(asio::ip::make_address("0.0.0.0", ec), 25565);

    asio::ip::tcp::socket socket(context);
    socket.connect(endpoint, ec);
    if (ec)
    {
        std::cout << "BAD\n";
        return ec.value();
    }

    std::string server = "localhost";

    // OUT
    minec::packet_buffer handshake(0x00);
    handshake.write_var_int(777); // protocol version
    handshake.write_string(server); // server address
    handshake.write_number<short>(25565); // port (25565 as usual)
    handshake.write_var_int(2); // intention LOGIN

    minec::packet_buffer login_start(0x00);
    //login_start.write_string(profile.username); // username
    //login_start.write_uuid(profile.uuid); // uuid
    login_start.write_string("test_bot"); // username
    login_start.write_uuid("4fed868c680c4fc28006e12e577c688d"); // uuid

    handshake.prep_and_send(socket, ec);
    login_start.prep_and_send(socket, ec);

    // IN
    minec::packet_buffer set_compression = minec::packet_buffer::receive(socket, ec, -1, false);
    set_compression.read_var_int();
    size_t compression_threshold = set_compression.read_var_int();
    minec::packet_buffer login_success = minec::packet_buffer::receive(socket, ec, compression_threshold, false);

    minec::packet_buffer login_acknowledged(0x3);
    login_acknowledged.prep_and_send(socket, ec, compression_threshold);

    minec::packet_buffer mcbrand_payload_in = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer server_links = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer update_enabled_features = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer select_known_packs_in = minec::packet_buffer::receive(socket, ec, compression_threshold, false);

    // OUT
    minec::packet_buffer mcbrand_payload_out(0x2);
    mcbrand_payload_out.write_string("minecraft:brand"); // channel
    mcbrand_payload_out.write_string("minec"); // minecraft client name
    mcbrand_payload_out.prep_and_send(socket, ec, compression_threshold);

    minec::packet_buffer client_information(0x0);
    client_information.write_string("en_us");
    client_information.write_number<uint8_t>(32); // render distance
    client_information.write_number<uint8_t>(0); // chat mode (enabled, commands only, hidden)
    client_information.write_number<bool>(true); // colored chat enabled?
    client_information.write_number<uint8_t>(0b01111111); // skin parts (bitmask): {0|hat|r. pants|l. pants|r. sleeve|l. sleeve|jacket|cape}
    client_information.write_number<bool>(true); // is main hand right?
    client_information.write_number<bool>(false); // enable chat filtering
    client_information.write_number<bool>(true); // allow server listing (should server list this bot?)
    client_information.write_var_int(2); // particle status (all, decreased, minimal)
    client_information.prep_and_send(socket, ec, compression_threshold);

    minec::packet_buffer select_known_packs_out(0x7);
    select_known_packs_out.write_var_int(1); // data packs array length
    select_known_packs_out.write_string("minecraft"); // data pack namespace
    select_known_packs_out.write_string("core"); // data pack name
    select_known_packs_out.write_string("26.3"); // mc version
    select_known_packs_out.prep_and_send(socket, ec, compression_threshold);

    minec::packet_buffer synchronize_registry_biomes = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_chat = minec::packet_buffer::receive(socket, ec, compression_threshold, false);

    minec::packet_buffer synchronize_registry_armor_trim_patterns = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_armor_trim_materials = minec::packet_buffer::receive(socket, ec, compression_threshold, false);

    minec::packet_buffer synchronize_registry_wolf_types = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_wolf_sounds = minec::packet_buffer::receive(socket, ec, compression_threshold, false);

    minec::packet_buffer synchronize_registry_pig_types = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_pig_sounds = minec::packet_buffer::receive(socket, ec, compression_threshold, false);

    minec::packet_buffer synchronize_registry_frog_types = minec::packet_buffer::receive(socket, ec, compression_threshold, false);

    minec::packet_buffer synchronize_registry_cat_types = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_cat_sounds = minec::packet_buffer::receive(socket, ec, compression_threshold, false);

    minec::packet_buffer synchronize_registry_cow_types = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_cow_sounds = minec::packet_buffer::receive(socket, ec, compression_threshold, false);

    minec::packet_buffer synchronize_registry_chicken_types = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_chicken_sounds = minec::packet_buffer::receive(socket, ec, compression_threshold, false);

    minec::packet_buffer synchronize_registry_nautilus_types = minec::packet_buffer::receive(socket, ec, compression_threshold, false);

    minec::packet_buffer synchronize_registry_paintings = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_dimension_type = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_damage_type = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_jukebox_songs = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_banner_pattern = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_instruments = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_enchantments = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_timeline = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_dialog = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_world_clock = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_test_environment = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_test_instance = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_sulfur_cube_archetype = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_decorated_pot_pattern = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_decorated_bock_transformer = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer synchronize_registry_block_state_provider = minec::packet_buffer::receive(socket, ec, compression_threshold, false);

    minec::packet_buffer update_tags = minec::packet_buffer::receive(socket, ec, compression_threshold, false);

    minec::packet_buffer finish_configuration = minec::packet_buffer::receive(socket, ec, compression_threshold, false);

    minec::packet_buffer acknowledge_finish_configuration(0x3);
    acknowledge_finish_configuration.prep_and_send(socket, ec, compression_threshold);

    minec::packet_buffer login = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    login.read_var_int();
    std::cerr << "  EntityID: " << login.read_number<int>() << '\n';
    std::cerr << "  IsHardcore: " << login.read_number<bool>() << '\n';
    std::cerr << "  Dimensions: " << '\n'; size_t len = login.read_var_int();
    for (; len > 0; --len)
        std::cerr << "  " << login.read_string();
    std::cerr << "  EntityID: " << login.read_var_int() << '\n';
    std::cerr << "  RenderDistance: " << login.read_var_int() << '\n';
    std::cerr << "  SimulationDistance: " << login.read_var_int() << '\n';
    std::cerr << "  ReducedDebugInfo: " << std::boolalpha << login.read_number<bool>() << '\n';
    std::cerr << "  EnableRespawnScreen: " << std::boolalpha << login.read_number<bool>() << '\n';
    std::cerr << "  DOLimitedCrafting: " << std::boolalpha << login.read_number<bool>() << '\n';
    std::cerr << "  DimensionType: " << login.read_var_int() << '\n';
    std::cerr << "  DimensionName: " << login.read_string() << '\n';
    std::cerr << "  HashedSeed: " << login.read_number<long>() << '\n';
    std::cerr << "  Gamemode: " << login.read_var_int() << '\n';
    std::cerr << "  PreviousGamemode: " << login.read_var_int() << '\n';
    std::cerr << "  IsDebug: " << std::boolalpha << login.read_number<bool>() << '\n';
    std::cerr << "  IsSuperflat: " << std::boolalpha << login.read_number<bool>() << '\n';
    bool has_death_location = login.read_number<bool>();
    std::cerr << "  HasDeathLocation: " << std::boolalpha << has_death_location << '\n'; if (has_death_location)
    {
        std::cerr << "    " << login.read_string() << '\n';
        std::cerr << "    " << login.read_position() << '\n';
    }
    std::cerr << "  PortalCooldown: " << login.read_var_int() << '\n';
    std::cerr << "  SeaLevel: " << login.read_var_int() << '\n';
    std::cerr << "  OnlineMode: " << std::boolalpha << login.read_number<bool>() << '\n';
    std::cerr << "  EnforcesSecureChat: " << std::boolalpha << login.read_number<bool>() << '\n';

    minec::packet_buffer ticking_state = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer ticking_step = minec::packet_buffer::receive(socket, ec, compression_threshold, false);

    minec::packet_buffer entity_event = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    entity_event.read_var_int();
    std::cerr << "EntityEvent: \n";
    std::cerr << "  EntityID:" << entity_event.read_number<int>() << '\n';
    std::cerr << "  Status:" << (int)entity_event.read_number<uint8_t>() << '\n';

    minec::packet_buffer change_difficulty = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    entity_event.read_var_int();
    std::cerr << "Change difficulty to: " << entity_event.read_var_int() << '\n';

    minec::packet_buffer commands = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    minec::packet_buffer set_camera = minec::packet_buffer::receive(socket, ec, compression_threshold, false);

    minec::packet_buffer update_advancements = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    std::cerr << update_advancements.read_var_int() << '\n';
/*
    minec::packet_buffer received = minec::packet_buffer::receive(socket, ec, compression_threshold, false);
    std::ofstream rec("rec.bin", std::ios::binary); for (auto a : received.buffer) {
        rec << a;
    }rec.close();*/
}