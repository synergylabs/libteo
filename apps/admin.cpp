#include <teo/teo.hpp>

#include <argparse/argparse.hpp>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <fmt/format.h>
#include <iostream>
#include <linenoise.h>
#include <string>
#include <thread>

using std::cout;
using std::endl;
using std::string;

static const size_t QR_CODE_WIDTH = 500;

void *PrintAdminDetail(void *admin_in)
{
    teo::Admin *admin_ptr = (teo::Admin *)admin_in;

    // Test QR code
    string admin_pubkey_b64 = teo::base64_encode(admin_ptr->get_keyset().get_full_pk());
    string user_qr_content_base = "{{ \"issuer\": \"admin\", \"type\": \"user\", \"Pubkey\":\"{}\", \"IP\": \"{}\", \"Port\": \"{}\" }}";
    string user_qr_content = fmt::format(user_qr_content_base, admin_pubkey_b64,
                                         admin_ptr->get_server_ip(), admin_ptr->get_server_port());

    CURL *curl = curl_easy_init();
    if (curl)
    {
        char *user_qr_output = curl_easy_escape(curl, user_qr_content.c_str(), user_qr_content.size());

        fmt::print("\nQR Code link for **user**: https://api.qrserver.com/v1/create-qr-code/?size={}x{}&data={}\n\n",
                   QR_CODE_WIDTH, QR_CODE_WIDTH, user_qr_output);
        fmt::print("User contents: {}\n", user_qr_content.c_str());

        curl_free(user_qr_output);
    }
    else
    {
        fmt::print("Error initiating CURL instance!");
    }

    return nullptr;
}

int main(int argc, char *argv[])
{
    argparse::ArgumentParser program("TEO Admin");

    program.add_argument("storage_ip")
        .help("IP address of the storage provider.");

    program.add_argument("storage_port")
        .help("Port number of the storage provider.")
        .action([](const std::string &value)
                { return std::stoi(value); });

    program.add_argument("device_pubkey")
        .help("Device public key in base64 encoding.");

    program.add_argument("device_secret")
        .help("Pre-shared device secrets for target device.");

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

    std::string storage_ip = program.get("storage_ip");
    int storage_port = program.get<int>("storage_port");

    string device_secret_b64_str = program.get("device_secret");
    string device_pubkey_b64 = program.get("device_pubkey");

    fmt::print("Running Admin node...\n\n");

    teo::api_initialize();

    teo::SharedSecretKey device_secret(teo::base64_decode(device_secret_b64_str));

    teo::Admin admin(storage_ip, storage_port, true);

    char *line;
    char *prgname = argv[0];

    std::string node_prefix = "teo-admin";
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
            else if (tokens[0] == "info")
            {
                fmt::print("Current client state info:\n");
                PrintAdminDetail(&admin);
            }
            else if (tokens[0] == "initdevice" || tokens[0] == "init")
            {
                fmt::print("Initializing target device...\n");
                admin.initialize_device(device_secret, device_pubkey_b64);
            }
            else if (tokens[0] == "storage")
            {
                bool malformat = false;
                if (tokens.size() == 3)
                {
                    // validate IP
                    std::string ip = tokens[1];
                    struct sockaddr_in sa;
                    int result = inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));
                    if (result != 1)
                    {
                        malformat = true;
                    }

                    int port = 0;
                    try
                    {
                        int port = std::stoi(tokens[2]);
                        if (port < 0 || port > 65536)
                        {
                            malformat = true;
                        }
                    }
                    catch (...)
                    {
                        malformat = true;
                    }

                    if (!malformat)
                    {
                        admin.set_storage_info(ip, port);
                        fmt::print("Successfully update storage information.\n");
                    }
                }
                else
                {
                    malformat = true;
                }

                if (malformat)
                {
                    fmt::print("Need to specify storage ip and port!\nTry type 'help'\n");
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