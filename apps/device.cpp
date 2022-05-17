// Partial code content referred from
// https://gist.github.com/syohex/b1aa695dc6ac5dced139

#include <teo/teo.hpp>

#include <argparse/argparse.hpp>
#include <chrono>
#include <curl/curl.h>
#include <fmt/format.h>
#include <iostream>
#include <linenoise.h>
#include <nlohmann/json.hpp>
#include <arpa/inet.h>
#include <string>
#include <thread>

typedef std::chrono::high_resolution_clock Clock;

static const size_t QR_CODE_WIDTH = 500;

teo::SharedSecretKey setup_key;

void *PrintDeviceDetail(void *dev_in, bool show_admin, bool show_user)
{

    teo::Device *dev_ptr = (teo::Device *)dev_in;

    std::string device_pubkey_b64 = teo::base64_encode(dev_ptr->get_keyset().get_full_pk());

    // Test QR code
    std::string setup_token_b64 = teo::base64_encode(setup_key.get_key(), teo::SharedSecretKey::KEY_SIZE);
    std::string admin_qr_content_base = "{{ \"issuer\": \"device\", \"type\": \"admin\", \"DeviceSecret\": \"{}\", \"Pubkey\":\"{}\", \"IP\": \"{}\", \"Port\": \"{}\" }}";
    std::string admin_qr_content = fmt::format(admin_qr_content_base, setup_token_b64, device_pubkey_b64, dev_ptr->get_server_ip(), dev_ptr->get_server_port());

    std::string user_qr_content_base = "{{ \"issuer\": \"device\", \"type\": \"user\", \"Pubkey\":\"{}\", \"IP\": \"{}\", \"Port\": \"{}\", \"admin\": \"{}\" }}";
    std::string user_qr_content = fmt::format(user_qr_content_base, device_pubkey_b64, dev_ptr->get_server_ip(), dev_ptr->get_server_port(), dev_ptr->get_admin_key_b64());

    fmt::print("==================================================================================================\n");

    fmt::print("General information:\n\tStorage IP: {}\n\tStorage port: {}\n",
               dev_ptr->get_storage_ip(),
               dev_ptr->get_storage_port());

    CURL *curl = curl_easy_init();
    if (curl)
    {
        char *admin_qr_output = curl_easy_escape(curl, admin_qr_content.c_str(), admin_qr_content.size());
        char *user_qr_output = curl_easy_escape(curl, user_qr_content.c_str(), user_qr_content.size());

        if (admin_qr_output && user_qr_output)
        {
            if (show_admin)
            {
                fmt::print("\nQR Code link for **admin**: https://api.qrserver.com/v1/create-qr-code/?size={}x{}&data={}\n\n",
                           QR_CODE_WIDTH, QR_CODE_WIDTH, admin_qr_output);
                auto admin_json_content = nlohmann::json::parse(admin_qr_content);
                fmt::print("Admin QR contents: {}\n", admin_json_content.dump(4));
            }

            if (show_user)
            {
                fmt::print("\nQR Code link for __user__: https://api.qrserver.com/v1/create-qr-code/?size={}x{}&data={}\n\n",
                           QR_CODE_WIDTH, QR_CODE_WIDTH, user_qr_output);
                auto user_json_content = nlohmann::json::parse(user_qr_content);
                fmt::print("User QR contents: {}\n", user_json_content.dump(4));
            }

            curl_free(admin_qr_output);
            curl_free(user_qr_output);
        }
    }
    else
    {
        fmt::print("Error initiating CURL instance!");
    }

    return nullptr;
}

bool validate_storage_info(const teo::Device *dev)
{
    return dev->get_storage_ip() != "" && dev->get_storage_port() != 0;
}

int main(int argc, char **argv)
{
    std::string storage_ip = "";
    int storage_port = 0;

    argparse::ArgumentParser program("TEO Device");

    program.add_argument("storage_ip")
        .help("IP address of the storage provider.");

    program.add_argument("storage_port")
        .help("Port number of the storage provider.")
        .action([](const std::string &value)
                { return std::stoi(value); });

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

    fmt::print("Running Device node...\n\n");

    teo::api_initialize();

    setup_key = teo::SharedSecretKey();
    teo::Device dev(setup_key, storage_ip, storage_port);

    char *line;
    char *prgname = argv[0];

    std::string node_prefix = "teo-device";
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
                bool show_admin = true;
                bool show_user = true;

                if (tokens.size() > 1)
                {
                    if (tokens[1] == "admin")
                    {
                        show_admin = true;
                        show_user = false;
                    }
                    else if (tokens[1] == "user")
                    {
                        show_admin = false;
                        show_user = true;
                    }
                }

                fmt::print("Current client state info:\n");
                PrintDeviceDetail(&dev, show_admin, show_user);
            }
            else if (tokens[0] == "test")
            {
                if (validate_storage_info(&dev))
                {
                    fmt::print("Test storing hello-world...\n");

                    auto before = Clock::now();
                    std::string test_hello_world_path = teo::getexepath(argv) + "/../../tests/hello-world.txt";
                    fmt::print("Hello world path: {}\n", test_hello_world_path);

                    teo::UUID metadata_uuid_hello_world;
                    if (dev.store_data(test_hello_world_path, &metadata_uuid_hello_world) != 0)
                    {
                        fmt::print("Test failed!!!\n");
                    }
                    else
                    {
                        auto after = Clock::now();
                        std::cout << "\tEncoding hello-world takes: "
                                  << std::dec
                                  << std::chrono::duration_cast<std::chrono::microseconds>(after - before).count()
                                  << " microseconds" << std::endl;
                    }
                }
                else
                {
                    fmt::print("Need to set up storage info first!\nTry type 'help'\n");
                }
            }
            else if (tokens[0] == "store")
            {
                bool malformat = false;
                teo::UUID metadata_uuid_result;
                if (tokens.size() == 2)
                {
                    std::string filepath = tokens[1];
                    if (dev.store_data(filepath, &metadata_uuid_result) != 0)
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
                    fmt::print("Need to specify path to file!\nTry type 'help'\n");
                }
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
                        dev.set_storage_info(ip, port);
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
            else if (tokens[0] == "beacon")
            {
                fmt::print("Enabling BLE Beaconing mode...\n");
                if (!teo::Device::COMPILED_WITH_BLE)
                {
                    fmt::print("TEO library wasn't compiled with BLE Beacon CMake option!\n");
                    fmt::print("You need to recompile it with flag -DTEO_BLUETOOTH_BEACON=ON!!\n");
                }
                else
                {
                    dev.enable_ble_beacon();
                }
            }
            else if (tokens[0] == "ownerinfo" || tokens[0] == "ownersinfo")
            {
                dev.print_owner_info();
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