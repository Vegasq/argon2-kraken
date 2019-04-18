#ifndef PWGEN_H
#define PWGEN_H

#include <random>
#include <string>
#include <chrono>
#include<iostream>
#include<fstream>

class PasswordGenerator
{
public:
    virtual void nextPassword(const void *&pw, std::size_t &pwSize) = 0;
};

class DummyPasswordGenerator : public PasswordGenerator
{
private:
    std::mt19937 gen;
    std::string currentPw;
    bool fileUsed = false;

    std::ifstream pwdFile;

    static constexpr std::size_t PASSWORD_LENGTH = 64;

public:
    DummyPasswordGenerator()
        : gen(std::chrono::system_clock::now().time_since_epoch().count())
    {
    }

    DummyPasswordGenerator(std::string file)
    {
        pwdFile.open(file);
        if (! pwdFile.is_open()) {
            std::cerr << "Error opening password file." << std::endl;
        }
        else {
            std::cout << "File " << file << " opened successfully." << std::endl;
            fileUsed = true;
        }
    }

    void nextPassword(const void *&pw, std::size_t &pwSize) override
    {
        currentPw.resize(PASSWORD_LENGTH);
        if (fileUsed) {
            getline(pwdFile, currentPw);
        }
        else {
            for (std::size_t i = 0; i < PASSWORD_LENGTH; i++) {
                currentPw[i] = (unsigned char)gen();
            }
        }
        pw = currentPw.data();
        pwSize = currentPw.size();
    }
};


#endif // PWGEN_H
