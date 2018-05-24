#include <array>
#include <iostream>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

using std::array;
using std::cin;
using std::cout;
using std::ostream;

auto constexpr bufferSize = 0x10000;

enum class PacketType {
    icmp = 1,
    igmp = 2,
    tcp = 6,
    udp = 17,
    igrp = 88,
    ospf = 89,
    other
};

auto getPacketType(unsigned char const *buffer) -> PacketType
{
    auto const *iph = reinterpret_cast<const iphdr *>(buffer);
    auto type = PacketType{};
    return static_cast<PacketType>(iph->protocol);
}

auto operator<<(ostream &out, PacketType type) -> ostream &
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
    case PacketType::igrp:
        out << "IGRP";
    case PacketType::ospf:
        out << "OSPF";
    default:
        cout << "other";
        break;
    }

    return out;
}

constexpr auto protocol(uint8_t code) -> char const *
{
    switch (code) {
    }
}

auto operator<<(ostream &out, iphdr const &hdr) -> ostream &
{
    auto source = sockaddr_in{};
    source.sin_addr.s_addr = hdr.saddr;
    auto dest = sockaddr_in{};
    dest.sin_addr.s_addr = hdr.daddr;

    out << "----------------- IP header ------------------\n"
        << " - IP version: " << hdr.version << "\n"
        << " - IP Header Length: " << hdr.ihl * sizeof(uint32_t) << " bytes\n"
        << " - Type of Service: " << hdr.tos << "\n"
        << " - IP Total Length: " << ntohs(hdr.tot_len) << " bytes\n"
        << " - Identification: " << ntohs(hdr.id) << "\n"
        << " - TTL: " << static_cast<int>(hdr.ttl) << "\n"
        << " - Protocol: " << static_cast<PacketType>(hdr.protocol) << "\n"
        << " - Checksum: " << ntohs(hdr.check) << "\n"
        << " - Source IP: " << inet_ntoa(source.sin_addr) << "\n"
        << " - Destination IP: " << inet_ntoa(dest.sin_addr) << "\n"
        << "----------------------------------------------\n";

    return out;
}

class TcpPacket
{
private:
    iphdr const *_iph = nullptr;
    tcphdr const *_tcph = nullptr;

public:
    TcpPacket(unsigned char const *buffer, ssize_t size)
        : _iph{reinterpret_cast<iphdr const *>(buffer)}
        , _tcph{reinterpret_cast<tcphdr const *>(
              buffer + (_iph->ihl * sizeof(uint32_t)))}
    {
    }

    friend ostream &operator<<(ostream &out, TcpPacket const &packet)
    {
        out << "================= TCP Packet =================\n"
            << *packet._iph << "\n";
        return out;
    }
};

auto main() -> int
{
    // ToDo use shared_ptr to share buffer between TcpPacket and buffer
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
        auto dataSize = recvfrom(sockRaw, buffer.data(), bufferSize, 0, &saddr,
                                 &saddrSize);

        if (dataSize < 0)
            cout << "recvfrom error, failed to get packets\n";

        cout << "Received bytes: " << dataSize << '\n';

        if (getPacketType(buffer.data()) == PacketType::tcp) {
            auto const packet = TcpPacket{buffer.data(), dataSize};
            cout << packet << "\n";
        }
    }

    cin.get();
    return 0;
}
