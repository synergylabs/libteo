//
// Created by han on 2/10/21.
//
#include <teo/teo.hpp>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <teo/client/Admin.hpp>

namespace teo
{
    Admin::Admin(const std::string &storage_ip,
                 int storage_port,
                 bool interactive)
    {
        this->interactive = interactive;

        set_server_port(default_admin_port);

        set_storage_info(storage_ip, storage_port);

        pthread_create(get_thread(ADMIN_THREAD_SERVER), nullptr, server_wrapper, this);

        register_ip_kms();

        LOGV("Client %d is Admin", get_id());
    }

    Admin::~Admin() {}

    int Admin::server_callback_handler(int connection)
    {
        MessageType incoming = network_read_message_type(connection);

        if (incoming == MessageType_ACQUIRE_PRE_AUTH_TOKEN_REQUEST)
        {
            return pre_auth_handler(connection);
        }

        return 0;
    }

    int Admin::initialize_device(SharedSecretKey &setup_key, std::string device_pubkey_b64)
    {
        std::string device_ip = default_device_ip;
        int device_port = default_device_port;

        if (!device_pubkey_b64.empty())
        {
            std::string device_pubkey = base64_decode(device_pubkey_b64);
            resolve_ip_kms(reinterpret_cast<const uint8_t *>(device_pubkey.c_str()),
                           device_pubkey.size(), device_ip, device_port);
        }

        return admin_initialize_device_impl(device_ip.c_str(), device_port,
                                            nullptr, AsymmetricEncryptionKeySet::FULL_PK_SIZE,
                                            setup_key, get_keyset());
    }

    int Admin::pre_auth_handler(int connection)
    {
        uint8_t request_buf[READ_BUFFER_SIZE];
        network_read(connection, request_buf, sizeof(request_buf));

        return admin_process_pre_auth_token_impl(request_buf, connection,
                                                 nullptr, nullptr, 
                                                 get_keyset(), this->interactive);
    }

}