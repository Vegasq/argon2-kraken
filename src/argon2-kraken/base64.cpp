std::string base64_decode(std::string encoded_str)
{
    std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string decoded_str;

    int padding = 0;
    int bits = 0;
    int count = 0;

    // Pad the input string with '=' characters if needed
    if (encoded_str.length() % 4 != 0)
    {
        encoded_str.append((4 - (encoded_str.length() % 4)), '=');
    }

    for (char c : encoded_str)
    {
        if (c == '=')
        {
            padding++;
        }
        else
        {
            bits = (bits << 6) | base64_chars.find(c);
        }

        count++;

        if (count == 4)
        {
            if (padding == 0)
            {
                decoded_str += static_cast<char>((bits >> 16) & 0xff);
                decoded_str += static_cast<char>((bits >> 8) & 0xff);
                decoded_str += static_cast<char>(bits & 0xff);
            }
            else if (padding == 1)
            {
                decoded_str += static_cast<char>((bits >> 10) & 0xff);
                decoded_str += static_cast<char>((bits >> 2) & 0xff);
            }
            else if (padding == 2)
            {
                decoded_str += static_cast<char>((bits >> 4) & 0xff);
                decoded_str += static_cast<char>((bits << 4) & 0xff);
            }
            else
            {
                // Handle error
            }

            bits = 0;
            count = 0;
            padding = 0;
        }
    }

    return decoded_str;
}