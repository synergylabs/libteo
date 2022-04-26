#include <teo/client/Storage.hpp>

#include <chrono>
#include <curl/curl.h>
#include <fmt/format.h>
#include <iostream>
#include <linenoise.h>
#include <nlohmann/json.hpp>
#include <pwd.h>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <unistd.h>

using decaf::Block;
using decaf::SecureBuffer;
using decaf::SpongeRng;

typedef typename teo::TEO_EC_Group::Scalar Scalar;
typedef typename teo::TEO_EC_Group::Point Point;

typedef std::chrono::high_resolution_clock Clock;

static const size_t QR_CODE_WIDTH = 500;

void *PrintStorageDetail(void *store_in)
{
    teo::Storage *store_ptr = (teo::Storage *)store_in;
    std::string store_pubkey_b64 = teo::base64_encode(store_ptr->get_keyset().get_full_pk());

    std::string user_qr_content_base = "{{ \"issuer\": \"storage\", \"type\": \"user\", \"Pubkey\":\"{}\", \"IP\": \"{}\", \"Port\": \"{}\" }}";
    std::string user_qr_content = fmt::format(user_qr_content_base, store_pubkey_b64, store_ptr->get_server_ip(),
                                              store_ptr->get_server_port());

    fmt::print("==================================================================================================\n");

    CURL *curl = curl_easy_init();
    if (curl)
    {
        char *user_qr_output = curl_easy_escape(curl, user_qr_content.c_str(), user_qr_content.size());
        fmt::print("QR Code link for user: https://api.qrserver.com/v1/create-qr-code/?size={}x{}&data={}\n\n",
                   QR_CODE_WIDTH, QR_CODE_WIDTH, user_qr_output);

        auto json_content = nlohmann::json::parse(user_qr_content);
        fmt::print("User contents: {}\n", json_content.dump(4));

        curl_free(user_qr_output);
    }

    fmt::print("==================================================================================================\n");

    // std::this_thread::sleep_for(std::chrono::seconds(10));

    return nullptr;
}

int main(int argc, char **argv)
{
    char *line;
    char *prgname = argv[0];

    /**
     * Set up TEO storage object
     */
    fmt::print("Running Storage node...\n\n");

    teo::api_initialize();

    teo::Storage store;

    /**
     * Prepare CLI parser loop
     */
    /* Now this is the main loop of the typical linenoise-based application.
     * The call to linenoise() will block as long as the user types something
     * and presses enter.
     *
     * The typed string is returned as a malloc() allocated string by
     * linenoise, so the user needs to free() it. */

    std::string node_prefix = "teo-storage";
    std::string history = node_prefix + "-history.txt";

    /* Load history from file. The history file is just a plain text file
     * where entries are separated by newlines. */
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
            if (tokens[0].compare("exit") == 0)
            {
                return 0;
            }
            else if (tokens[0].compare("help") == 0)
            {
                print_usage = true;
            }
            else if (tokens[0].compare("info") == 0)
            {
                fmt::print("Current client state info:\n");
                PrintStorageDetail(&store);
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
