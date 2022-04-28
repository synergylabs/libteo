#include <teo/teo.hpp>
#include <fmt/format.h>
#include <argparse/argparse.hpp>
#include <string>
#include <iostream>
#include <curl/curl.h>
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

    program.add_argument("--reps")
        .help("Test repetitions.")
        .default_value(1)
        .action([](const std::string &value)
                { return std::stoi(value); });

    program.add_argument("metadata_UUID")
        .help("UUID for request.");

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

    std::string metadata_uuid = program.get("metadata_UUID");

    std::string storage_ip = program.get("storage_ip");
    int storage_port = program.get<int>("storage_port");

    int reps = program.get<int>("--reps");
    fmt::print("reps: {}\n", reps);

    fmt::print("\nRunning Accessor node...\n\n");

    teo::api_initialize();

    teo::Accessor acc(storage_ip, storage_port);

    teo::UUID metadataUUID(metadata_uuid);

    std::string res = "";
    res += "sieve_dec_timer,sym_dec_timer,download_timer,total_timer\n";

    for (int i = 0; i < reps; i++)
    {
        int sieve_dec_timer, sym_dec_timer, download_timer;
        std::chrono::high_resolution_clock::time_point timer_start, timer_stop;

        timer_start = std::chrono::high_resolution_clock::now();

        try
        {
            if (acc.request_access(metadataUUID, "", (i != 0), false,
                                   &sieve_dec_timer, &sym_dec_timer, &download_timer) != 0)
            {
                fmt::print("Access failed!! Exit prematurely!!!\n");
                return -1;
            }

            timer_stop = std::chrono::high_resolution_clock::now();
            int total_timer = std::chrono::duration_cast<std::chrono::milliseconds>(timer_stop - timer_start).count();

            res += fmt::format("{},{},{},{}\n",
                               sieve_dec_timer,
                               sym_dec_timer,
                               download_timer,
                               total_timer);
        }
        catch (...)
        {
            fmt::print("encounter error...\n");
        }

        std::cout << "Press ENTER to continue to the next iteration using cached key..." << std::endl;
        std::string tmp;
        std::getline(std::cin, tmp);
    }

    fmt::print("Timer Result:\n{}", res);

    return 0;
}