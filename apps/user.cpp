#include <teo/teo.hpp>
#include <fmt/format.h>
#include <argparse/argparse.hpp>
#include <string>
#include <iostream>
#include <curl/curl.h>
#include <linenoise.h>

using std::cout;
using std::endl;
using std::string;

static const size_t QR_CODE_WIDTH = 500;

int main(int argc, char *argv[])
{
    std::string storage_ip = "";
    int storage_port = 0;

    argparse::ArgumentParser program("TOT User");

    program.add_argument("storage_ip")
        .help("IP address of the storage provider.");

    program.add_argument("storage_port")
        .help("Port number of the storage provider.")
        .action([](const std::string &value)
                { return std::stoi(value); });

    program.add_argument("admin_pubkey")
        .help("Admin public key in base64 encoding.");

    program.add_argument("device_pubkey")
        .help("Device's public key in base64 encoding.");

    try
    {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error &err)
    {
        std::cout << err.what() << std::endl;
        std::cout << program;
        exit(0);
    }

    storage_ip = program.get("storage_ip");
    storage_port = program.get<int>("storage_port");

    string admin_pubkey_b64 = program.get("admin_pubkey");
    string device_pubkey_b64 = program.get("device_pubkey");

    fmt::print("Running User node...\n\n");

    teo::api_initialize();

    teo::User user(reinterpret_cast<const uint8_t *>(teo::base64_decode(admin_pubkey_b64).c_str()),
                   "0.0.0.0", 9011,
                   storage_ip, storage_port,
                   true);

    // // Generate access certificate
    // const char msg[] = "authorized user";
    // size_t msg_len = sizeof(msg);
    // uint8_t *cert = nullptr;
    // size_t cert_len = 0;
    // user.sign_access_cert(reinterpret_cast<const uint8_t *>(msg), msg_len, &cert, &cert_len);
    // string msg_b64 = teo::base64_encode(reinterpret_cast<const uint8_t *>(msg), msg_len);
    // string cert_b64 = teo::base64_encode(cert, cert_len);

    // fmt::print("Msg content: {}\n", msg_b64);
    // fmt::print("Cert content: {}\n", cert_b64);

    // user.wait_all();

    char *line;
    char *prgname = argv[0];

    std::string node_prefix = "teo-user";
    std::string history = node_prefix + "-history.txt";
    linenoiseHistoryLoad(history.c_str()); /* Load the history at startup */

    while ((line = linenoise((node_prefix + "> ").c_str())) != NULL)
    {
        /* Do something with the string. */
        if (line[0] != '\0')
        {
#if !defined(NDEBUG)
            printf("[debug] echo: '%s'\n", line);
#endif

            std::string full_line(line);
            std::transform(full_line.begin(), full_line.end(), full_line.begin(),
                           [](unsigned char c)
                           { return std::tolower(c); });
            std::istringstream iss(full_line);
            std::vector<std::string> tokens{std::istream_iterator<std::string>{iss},
                                            std::istream_iterator<std::string>{}};

            bool print_usage = false;
            assert(tokens.size() > 0);
            if (tokens[0] == "exit")
            {
                return 0;
            }
            else if (tokens[0] == "help")
            {
                print_usage = true;
            }
            else if (tokens[0] == "preauth")
            {
                fmt::print("Seeking pre-auth token from admin...\n");
                user.acquire_pre_auth_token();
            }
            else if (tokens[0] == "claimdevice" || tokens[0] == "claim")
            {
                fmt::print("Claiming target device...\n");
                user.claim_device(false, device_pubkey_b64);
            }
            else if (tokens[0] == "reencrypt")
            {
                bool malformat = false;
                if (tokens.size() == 2)
                {
                    teo::UUID metadataUUID;
                    try
                    {
                        metadataUUID = teo::UUID(tokens[1]);
                        user.re_encrypt(metadataUUID);
                    }
                    catch (...)
                    {
                        malformat = true;
                    }
                }
                else
                {
                    malformat = true;
                }

                if (malformat)
                {
                    fmt::print("Need to specify metadata UUID!\nTry type 'help'\n");
                }
            }

            if (print_usage)
            {
                // TODO: print usage
            }

            linenoiseHistoryAdd(line);             /* Add to the history. */
            linenoiseHistorySave(history.c_str()); /* Save the history on disk. */
        }
        free(line);
    }

    return 0;
}