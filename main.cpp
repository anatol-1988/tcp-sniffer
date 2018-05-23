#include <array>
#include <iostream>

#include <netinet/in.h>
#include <sys/socket.h>

using std::array;
using std::cin;
using std::cout;

auto constexpr bufferSize = 0x10000;

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
    }

    cin.get();
    return 0;
}
