#include <teo/teo.hpp>

#include <argparse/argparse.hpp>
#include <curl/curl.h>
#include <fmt/format.h>
#include <iostream>
#include <linenoise.h>
#include <string>
#include <thread>

using std::cout;
using std::endl;
using std::string;

const int SLEEP_INTERVAL = 500; // in milliseconds

int main(int argc, char *argv[])
{
    argparse::ArgumentParser program("TEO Accessor");

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

    std::string storage_ip = program.get("storage_ip");
    int storage_port = program.get<int>("storage_port");

    fmt::print("\nRunning Accessor node...\n\n");

    teo::api_initialize();

    teo::Accessor acc(storage_ip, storage_port);

    char *line;
    char *prgname = argv[0];

    std::string node_prefix = "teo-accessor";
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
            else if (tokens[0] == "request")
            {
                bool malformat = false;
                if (tokens.size() == 2)
                {
                    teo::UUID metadataUUID(tokens[1]);
                    try
                    {
                        if (acc.request_access(metadataUUID, "", false, false,
                                               nullptr, nullptr, nullptr,
                                               true) != 0)
                        {
                            fmt::print("Access failed!! Exit!!!\n");
                            return -1;
                        }
                        else
                        {
                            fmt::print("Successfully decrypted data!\n");
                        }
                    }
                    catch (...)
                    {
                        fmt::print("Access failed!! Exit!!!\n");
                        return -1;
                    }
                }
                else
                {
                    malformat = true;
                }

                if (malformat)
                {
                    fmt::print("Need to specify metadata UUID!\n");
                }
            }
            else if (tokens[0] == "retryfromcache")
            {
                bool malformat = false;
                if (tokens.size() == 2)
                {
                    teo::UUID metadataUUID(tokens[1]);
                    try
                    {
                        if (acc.request_access(metadataUUID, "", true, false,
                                               nullptr, nullptr, nullptr,
                                               false) != 0)
                        {
                            fmt::print("Access failed!! Exit!!!\n");
                            return -1;
                        }
                        else
                        {
                            fmt::print("Successfully decrypted data!\n");
                        }
                    }
                    catch (...)
                    {
                        fmt::print("Access failed!! Exit!!!\n");
                        return -1;
                    }
                }
                else
                {
                    malformat = true;
                }

                if (malformat)
                {
                    fmt::print("Need to specify metadata UUID!\n");
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