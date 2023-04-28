#include <sstream>


std::string hexToString(const std::string hex_string)
{
    std::string hash;
    for (std::size_t i = 0; i < hex_string.length(); i += 2)
    {
        std::string byte_hex = hex_string.substr(i, 2);
        char byte = (char)strtol(byte_hex.c_str(), nullptr, 16);
        hash += byte;
    }
    return hash;
}

std::string stringToHex(const std::string &input)
{
    std::stringstream ss;
    ss << std::hex << std::uppercase;

    for (size_t i = 0; i < input.length(); ++i)
    {
        int intValue = static_cast<unsigned char>(input[i]);
        ss << ((intValue < 16) ? "0" : "") << intValue;
    }

    return ss.str();
}