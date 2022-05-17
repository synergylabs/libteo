//
// Created by han on 2/11/21.
//

#ifndef TEO_DEVICE_HPP
#define TEO_DEVICE_HPP

#include <vector>
#include <string>
#include <deque>
#include <unordered_map>

#include <teo/SharedSecretKey.hpp>

namespace teo
{

    class Device : public Client
    {
    private:
        static const int DEVICE_THREAD_SERVER = 0;
        static const int DEVICE_THREAD_INFO_PRITNER = 1;
        static const int DEVICE_THREAD_BEACON = 2;
        static const int DEVICE_THREAD_PROXIMITY_DETECT = 3;

        const std::string BEACON_ENABLE_BLE_ADVERTISE = "sudo hciconfig hci0 leadv 3";
        const std::string BEACON_PREFIX = "sudo hcitool -i hci0 cmd 0x08 0x0008 1f 02 01 06 03 03 aa fe 17 16 aa fe 10 00";
        static const int DEFAULT_BLE_BEACON_MSG_HISTORY_LEN = 10; // max entries of epoches stored in history
        static const int DEFAULT_BLE_BEACON_EPOCH_INTERVAL = 20;  // in seconds, beacon refresh intervals
        static const int DEFAULT_BLE_BEACON_TIMEOUT_LIM = 5;      // max number of epoches before an owner is inactive

        uint8_t valid_device_proof[AsymmetricEncryptionKeySet::SIGNATURE_SIZE]{0};
        SharedSecretKey setup_key;
        uint8_t admin_key[AsymmetricEncryptionKeySet::FULL_PK_SIZE]{};

#if defined(TEO_STANDALONE_APP) && defined(TEO_BLUETOOTH_BEACON)
        bool ble_beacon_enable = false; // master switch for BLE beacon mode
        int ble_beacon_msg_history_len = DEFAULT_BLE_BEACON_MSG_HISTORY_LEN;
        int ble_beacon_epoch_interval = DEFAULT_BLE_BEACON_EPOCH_INTERVAL;
        int ble_beacon_timeout_lim = DEFAULT_BLE_BEACON_TIMEOUT_LIM;
        std::deque<std::string> ble_beacon_msgs;
        std::unordered_map<std::string, int> ble_beacon_owner_hb_count;

        void ble_beacon_history_add(std::string &msg);
        void ble_beacon_history_trim();
#endif

        std::vector<const uint8_t *> owner_keys;
        std::unordered_map<std::string, bool> real_time_perm;
        int set_owner(uint8_t *pk, bool group_mode = false);
        void flush_owner_key();
        bool is_group();

    public:
        Device();

        explicit Device(SharedSecretKey &setup_key_in,
                        const std::string &storage_ip = default_storage_ip,
                        int storage_port = default_storage_port);

        ~Device();

        bool has_owner();

        int server_callback_handler(int connection) override;

        int accept_initialization_handler(int connection);

        int acquire_ownership_handler(int connection);

        int release_device_handler(int connection);

        int release_device_owner(std::string owner_pk_b64);

        int remove_real_time_access_handler(int connection);

        int process_heartbeat_handler(int connection);

        int store_data(const std::string &file_path,
                       UUID *sieve_block_result = nullptr,
                       int *sieve_enc_timer = nullptr,
                       int *sym_enc_timer = nullptr,
                       int *upload_timer = nullptr,
                       int *sieve_nego_timer = nullptr,
                       int *upload_notify_timer = nullptr);

        int store_data(const uint8_t *file_content_ptr,
                       size_t file_content_len,
                       UUID *sieve_block_result = nullptr,
                       int *sieve_enc_timer = nullptr,
                       int *sym_enc_timer = nullptr,
                       int *upload_timer = nullptr,
                       int *sieve_nego_timer = nullptr,
                       int *upload_notify_timer = nullptr);

        int store_data_teo_impl(UUID *sieve_block_result,
                                const std::string &file_path,
                                const uint8_t *input_buf,
                                size_t input_buf_len,
                                int *sieve_enc_timer,
                                int *sym_enc_timer,
                                int *upload_timer,
                                int *sieve_nego_timer,
                                int *upload_notify_timer);

        int verify_certification(const uint8_t *m_ptr,
                                 size_t m_len,
                                 const uint8_t *s_ptr,
                                 size_t s_len);

        int encrypt_file_local(SharedSecretKey &data_key, const std::string &file_path, const std::string &encrypted_file_path);

        int encrypt_content_local(SharedSecretKey &data_key, const uint8_t *input_buf, size_t input_buf_len,
                                  uint8_t **encrypted_file_buf, size_t *encrypted_file_buf_len);

        bool real_time_access();

        std::string get_admin_key_b64();

        void print_owner_info();

#if defined(TEO_STANDALONE_APP) && defined(TEO_BLUETOOTH_BEACON)
        static const bool COMPILED_WITH_BLE = true;
#else
        static const bool COMPILED_WITH_BLE = false;
#endif
        static void *beacon_wrapper(void *obj);

        int launch_beacon();

        int enable_ble_beacon(int epoch_interval = DEFAULT_BLE_BEACON_EPOCH_INTERVAL,
                              int timeout_lim = DEFAULT_BLE_BEACON_TIMEOUT_LIM,
                              int history_len = DEFAULT_BLE_BEACON_MSG_HISTORY_LEN);

        int disable_ble_beacon();
    };
}

#endif // TEO_DEVICE_HPP
