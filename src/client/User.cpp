//
// Created by han on 2/19/21.
//

#include <teo/teo.hpp>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <chrono>
#include <thread>

#if defined(TEO_STANDALONE_APP)
#include <iostream>
#include <linenoise.h>
#endif

namespace teo
{
    User::User(const uint8_t *admin_pubkey_in, const std::string &user_ip, short user_port,
               const std::string &storage_ip, int storage_port, bool interactive)
    {
        this->interactive = interactive;

        set_server_port(user_port);
        set_server_ip(user_ip);

        set_storage_info(storage_ip, storage_port);

        pthread_create(get_thread(USER_THREAD_SERVER), nullptr,
                       server_wrapper, this);

        if (admin_pubkey_in != nullptr)
        {
            memcpy(admin_pubkey, admin_pubkey_in, sizeof(admin_pubkey));
            resolve_ip_kms(admin_pubkey, AsymmetricEncryptionKeySet::FULL_PK_SIZE,
                           admin_ip, admin_port);
            if (admin_port == 0)
            {
                admin_port = default_admin_port;
            }
        }
        // Register user ip and port to KMS
        register_ip_kms();

        LOGV("Client %d is User\n", get_id());
    }

    User::~User() {}

    int User::server_callback_handler(int connection)
    {
        MessageType incoming = network_read_message_type(connection);

        if (incoming == MessageType_DATA_STORE_SIEVE_CRED_REQUEST)
        {
            return data_store_handler(connection);
        }
        else if (incoming == MessageType_DATA_ACCESS_FETCH)
        {
            return data_access_handler(connection);
        }

        return 0;
    }

    int User::acquire_pre_auth_token()
    {
        return user_acquire_pre_auth_token_impl(admin_ip.c_str(), admin_port, admin_pubkey,
                                                get_keyset(), pre_auth_token);
    }

    int User::claim_device(bool exclusive, std::string device_pubkey_b64)
    {
        std::string device_ip = default_device_ip;
        int device_port = default_device_port;

        if (!device_pubkey_b64.empty())
        {
            std::string device_pubkey = base64_decode(device_pubkey_b64);
            resolve_ip_kms(reinterpret_cast<const uint8_t *>(device_pubkey.c_str()),
                           device_pubkey.size(), device_ip, device_port);
            if (device_port == 0)
            {
                device_port = default_device_port;
            }
        }

        return user_claim_device_impl(get_keyset(), pre_auth_token, device_ip.c_str(), device_port,
                                      admin_pubkey, exclusive, claimed_device, sizeof(claimed_device));
    }

    int User::data_store_handler(int connection)
    {
        uint8_t request_buf[READ_BUFFER_SIZE];
        network_read(connection, request_buf, sizeof(request_buf));

        SieveKey sieve_key;

        uint8_t request_pubkey[AsymmetricEncryptionKeySet::FULL_PK_SIZE]{};

        int err = user_process_sieve_cred_request_impl(request_buf,
                                                       connection,
                                                       nullptr,
                                                       nullptr,
                                                       get_keyset(),
                                                       sieve_key,
                                                       claimed_device,
                                                       sizeof(claimed_device),
                                                       request_pubkey,
                                                       sizeof(request_pubkey));

        if (err != 0)
        {
            LOGW("Error handling Sieve credential request");
            return -1;
        }

        if (network_read_message_type(connection) != MessageType_DATA_STORE_UPLOAD_NOTIFICATION)
        {
            LOGW("Unexpected data upload notification message type");
            return -1;
        }

        uint8_t notification_buf[READ_BUFFER_SIZE];
        network_read(connection, notification_buf, sizeof(notification_buf));

        UUID metadata_UUID;
        UUID sieve_data_UUID;

        err = user_process_upload_notification_impl(notification_buf,
                                                    request_pubkey,
                                                    get_keyset(),
                                                    metadata_UUID,
                                                    sieve_data_UUID);

        if (err != 0)
        {
            LOGW("Fail to process device's data upload notification!");
            return -1;
        }

        // Store session key and ID for later use...
        sieve_data_key_lookup[sieve_data_UUID] = sieve_key;
        metadata_sieve_lookup[metadata_UUID] = sieve_data_UUID;
        sieve_metadata_lookup[sieve_data_UUID] = metadata_UUID;

        return 0;
    }

    int User::data_access_handler(int conn)
    {
        // Construct request input
        uint8_t fetch_buf[READ_BUFFER_SIZE]{};
        network_read(conn, fetch_buf, sizeof(fetch_buf));

        CiphertextDataAccessFetch fetch_payload;
        uint8_t accessor_pubkey[AsymmetricEncryptionKeySet::FULL_PK_SIZE]{};

        int err = user_process_data_access_fetch_1_impl(fetch_buf,
                                                        get_keyset(),
                                                        fetch_payload,
                                                        accessor_pubkey,
                                                        sizeof(accessor_pubkey));
        if (err != 0)
        {
            LOGW("Error processing fetch request payload");
            return -1;
        }

        UUID sieve_uuid(fetch_payload.sieve_data_block_uuid,
                        sizeof(fetch_payload.sieve_data_block_uuid));

        if (!delegate_access(sieve_uuid,
                             accessor_pubkey,
                             sizeof(accessor_pubkey)))
        {
            LOGI("Access denied");
            return -1;
        }

        if (sieve_data_key_lookup.find(sieve_uuid) == sieve_data_key_lookup.end())
        {
            LOGW("Sieve uuid not found: %s", sieve_uuid.get_uuid().c_str());
            return -1;
        }

        user_process_data_access_fetch_2_impl(conn,
                                              nullptr,
                                              nullptr,
                                              get_keyset(),
                                              sieve_data_key_lookup[sieve_uuid],
                                              fetch_payload,
                                              accessor_pubkey);

        return 0;
    }

    bool User::delegate_access(const UUID &sieve_uuid, const uint8_t *request_pubkey, size_t request_pubkey_len)
    {
        // FIXME: Add your custom access control code here
        bool grant = true;
#if defined(TEO_STANDALONE_APP)
        if (interactive)
        {
            linenoisePause();

            bool answer_valid = false;
            std::string answer;

            do
            {
                std::cout << "Do you want to grant this data access? [y/n]: ";
                std::getline(std::cin, answer);

                if (answer.length() == 0)
                {
                    // Empty line, enter pressed
                    answer_valid = false;
                }
                else
                {

                    std::transform(answer.begin(), answer.end(), answer.begin(), ::tolower);

                    answer_valid =
                        (answer == "y") ||
                        (answer == "n") ||
                        (answer == "yes") ||
                        (answer == "no");
                }

                if (!answer_valid || ((answer == "n") ||
                                      (answer == "no")))
                {
                    grant = false;
                }
                else
                {
                    grant = true;
                }
            } while (!answer_valid);

            linenoiseResume();
        }
#endif
        return grant;
    }

    int User::re_encrypt(const UUID &block_uuid, const uint8_t *storage_pk)
    {
        const UUID *sieve_data_block_uuid = nullptr;
        const UUID *metadata_uuid = nullptr;
        if (sieve_data_key_lookup.find(block_uuid) == sieve_data_key_lookup.end())
        {
            // block_uuid is the metadata block UUID
            // Try look up Sieve block from metadata
            if (metadata_sieve_lookup.find(block_uuid) == metadata_sieve_lookup.end())
            {
                LOGW("Sieve data UUID not found");
                return -1;
            }

            sieve_data_block_uuid = &metadata_sieve_lookup[block_uuid];
            metadata_uuid = &block_uuid;
        }
        else
        {
            // block_uuid is the Sieve block
            // Try search for the metadata block UUID
            if (sieve_metadata_lookup.find(block_uuid) == sieve_metadata_lookup.end())
            {
                LOGW("Corresponding metadata UUID not found");
                return -1;
            }

            sieve_data_block_uuid = &block_uuid;
            metadata_uuid = &sieve_metadata_lookup[block_uuid];
        }

        SieveKey sieve_key_new;
        RekeyToken token = sieve_data_key_lookup[*sieve_data_block_uuid].gen_rekey_token(sieve_key_new);

        int err = user_re_encrypt_impl(*metadata_uuid,
                                       *sieve_data_block_uuid,
                                       token,
                                       storage_pk,
                                       get_storage_ip().c_str(),
                                       get_storage_port(),
                                       get_keyset());

        if (err == 0)
        {
            sieve_data_key_lookup[*sieve_data_block_uuid].apply_rekey_token_key(token);
        }
        else
        {
            LOGW("Error in processing re-encrypt impl!");
            return -1;
        }

        return 0;
    }

    void User::wait_all()
    {
        void *status;

        LOGI("User %d is waiting for all threads...", get_id());

        for (unsigned long thread : threads)
        {
            pthread_join(thread, &status);
        }
    }

    int User::sign_access_cert(const uint8_t *msg, size_t msg_len, uint8_t **cert_ptr, size_t *cert_len_ptr)
    {
        if (*cert_ptr != nullptr)
        {
            delete[](*cert_ptr);
        }

        *cert_len_ptr = AsymmetricEncryptionKeySet::SIGNATURE_SIZE;
        (*cert_ptr) = new uint8_t[*cert_len_ptr]{};
        std::cout << "About to sign" << std::endl;
        get_keyset().sign_detached(*cert_ptr, msg, msg_len);
        std::cout << "Finish sign" << std::endl;

        return 0;
    }

}