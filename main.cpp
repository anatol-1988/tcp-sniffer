#include <array>
#include <iostream>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>

using std::array;
using std::cin;
using std::cout;
using std::ostream;

auto constexpr bufferSize = 0x10000;

enum class PacketType { icmp = 1, igmp = 2, tcp = 6, udp = 17, other };

auto getPacketType(unsigned char const* buffer) -> PacketType
{
    auto const* iph = reinterpret_cast<const iphdr*>(buffer);
    auto type = PacketType{};
    return static_cast<PacketType>(iph->protocol);
}

ostream& operator<<(ostream &out, PacketType type)
{
    switch (type) {
    case PacketType::icmp:
        out << "ICMP";
        break;
    case PacketType::igmp:
        out << "IGMP";
        break;
    case PacketType::tcp:
        out << "TCP";
        break;
    case PacketType::udp:
        out << "UDP";
        break;
    default:
        cout << "other";
        break;
    }

    return out;
}

auto main() -> int
{
    auto buffer = array<unsigned char, bufferSize>{};

    cout << "Starting sniffer\n";
    auto sockRaw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (sockRaw < 0) {
        cout << "Socket Error\n";
        cin.get();
        return 1;
    }

    while (true) {
        auto saddr = sockaddr{};
        auto saddrSize = socklen_t{sizeof saddr};
        auto dataSize
            = recvfrom(sockRaw, &buffer, bufferSize, 0, &saddr, &saddrSize);

        if (dataSize < 0)
            cout << "recvfrom error, failed to get packets\n";

        cout << "Received bytes: " << dataSize << '\n';
        cout << "Type: " << getPacketType(buffer.data()) << '\n';
    }

    cin.get();
    return 0;
}
