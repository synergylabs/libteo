#include <chrono>
#include <thread>
#include <unordered_map>
#include <vector>

#include "teo/client/Accessor.hpp"
#include "teo/teo_helper.hpp"
#include "teo/teo_logger.hpp"
#include "teo/teo_file_io.hpp"
#include "teo/base64.hpp"
#include "teo/CipherType.hpp"

namespace teo
{
    Accessor::Accessor(const std::string &storage_ip,
                       int storage_port)
    {
        set_storage_info(storage_ip, storage_port);
        register_ip_kms();

        LOGV("Client %d is Accessor\n", get_id());
    }

    Accessor::~Accessor() {}

    int Accessor::request_access(const UUID &metadata_uuid, std::string orig_file_path,
                                 bool from_cache, bool exp_fail,
                                 int *sieve_dec_timer, int *sym_dec_timer, int *download_timer,
                                 bool store_output)
    {
        int err = 0;
        int conn = 0;

        char *metadata_buf = nullptr;
        uint8_t *accessor_pubkey = nullptr;

        accessor_pubkey = new uint8_t[AsymmetricEncryptionKeySet::FULL_PK_SIZE];
        get_keyset().get_full_pk(accessor_pubkey, AsymmetricEncryptionKeySet::FULL_PK_SIZE);

        flatbuffers::FlatBufferBuilder parent_builder(G_FBS_SIZE);

        /*
         Download metadata block
         */
        metadata_buf = nullptr;
        size_t metadata_buf_len = 0;

        conn = network_connect(get_storage_ip().c_str(), get_storage_port());
        err = download_file(conn, metadata_uuid, &metadata_buf, &metadata_buf_len);

        if (err != 0)
        {
            return -1;
        }
        auto metadata_content = MetadataBlock::GetMetadataBlock(metadata_buf);

        /*
         Fetch Sieve key from each owner
        */
        std::unordered_map<std::string, SieveKey> owner_sieve_keys;
        std::unordered_map<std::string, int> owner_sockfd;
        if (!from_cache)
        {
            std::vector<std::thread *> fetch_sieve_key_t;
            auto fetch_sieve_key_lambda = [&](const MetadataBlock::OwnerInfo *owner_info)
            {
                std::unique_lock<std::mutex> data_lock(g_data_mutex, std::defer_lock);
                flatbuffers::FlatBufferBuilder builder(G_FBS_SIZE);

#if !defined(NDEBUG)
                hexprint(owner_info->owner_pubkey()->data(), owner_info->owner_pubkey()->size());
#endif
                LOGV("This owner's Sieve data UUID: %s", owner_info->sieve_data_uuid()->data());

                std::string owner_key_b64 = base64_encode(owner_info->owner_pubkey()->data(),
                                                          owner_info->owner_pubkey()->size());

                builder.Clear();
                // Get data owner ip/port
                int conn = connect_user_kms(owner_info->owner_pubkey()->data(),
                                            owner_info->owner_pubkey()->size());
                data_lock.lock();
                owner_sockfd[owner_key_b64] = conn;
                data_lock.unlock();
                if (owner_sockfd[owner_key_b64] <= 0)
                {
                    LOGW("Error establishing connection with data owner");
                    return -1;
                }

                CiphertextDataAccessFetch fetch_payload;
                fetch_payload.type = CipherType::data_access_fetch;
                memcpy(fetch_payload.sieve_data_block_uuid,
                       owner_info->sieve_data_uuid()->data(),
                       owner_info->sieve_data_uuid()->size());
                random_buf(fetch_payload.random_challenge, sizeof(fetch_payload.random_challenge));

                size_t fetch_ciphertext_len = AsymmetricEncryptionKeySet::get_box_easy_cipher_len(sizeof(fetch_payload));
                auto fetch_ciphertext = new uint8_t[fetch_ciphertext_len]{};
                uint8_t msg_nonce[AsymmetricEncryptionKeySet::NONCE_SIZE]{0};
                get_keyset().box_easy(fetch_ciphertext, fetch_ciphertext_len,
                                      reinterpret_cast<uint8_t *>(&fetch_payload),
                                      sizeof(fetch_payload), msg_nonce, owner_info->owner_pubkey()->data());

                auto accessor_pubkey_obj = builder.CreateVector(accessor_pubkey,
                                                                AsymmetricEncryptionKeySet::FULL_PK_SIZE);
                auto fetch_nonce_obj = builder.CreateVector(msg_nonce, sizeof(msg_nonce));
                auto fetch_ciphertext_obj = builder.CreateVector(fetch_ciphertext, fetch_ciphertext_len);
                auto fetch_msg = CreateDataAccessFetch(builder,
                                                       accessor_pubkey_obj,
                                                       fetch_nonce_obj,
                                                       fetch_ciphertext_obj);
                builder.Finish(fetch_msg);

                network_send_message_type(owner_sockfd[owner_key_b64], MessageType_DATA_ACCESS_FETCH);
                network_send(owner_sockfd[owner_key_b64], builder.GetBufferPointer(), builder.GetSize());

                // Process authorization response from data owner
                if (network_read_message_type(owner_sockfd[owner_key_b64]) != MessageType_DATA_ACCESS_RESPONSE)
                {
                    LOGV("Unexpected data access response");
                    return -1;
                }

                uint8_t response_buf[READ_BUFFER_SIZE];
                network_read(owner_sockfd[owner_key_b64], response_buf, READ_BUFFER_SIZE);
                auto response_msg = GetDataAccessResponse(response_buf);

                CiphertextDataAccessResponse response_payload;
                get_keyset().box_open_easy(reinterpret_cast<uint8_t *>(&response_payload), sizeof(response_payload),
                                           response_msg->ciphertext()->data(), response_msg->ciphertext()->size(),
                                           response_msg->msg_nonce()->data(),
                                           owner_info->owner_pubkey()->data());

                if (response_payload.type != CipherType::data_access_response)
                {
                    LOGW("Incorrect respose type");
                    return -1;
                }

                if (memcmp(fetch_payload.random_challenge,
                           response_payload.random_challenge_response,
                           sizeof(fetch_payload.random_challenge)) != 0)
                {
                    LOGW("Incorrect random noise responded");
                    return -1;
                }

                data_lock.lock();
                owner_sieve_keys[owner_key_b64] = SieveKey(response_payload.sieve_key,
                                                           sizeof(response_payload.sieve_key),
                                                           owner_info->sieve_nonce()->data(),
                                                           owner_info->sieve_nonce()->size());
                data_lock.unlock();

                delete[] fetch_ciphertext;
                return 0;
            };

            for (int i = 0; i < metadata_content->owners()->size(); i++)
            {
                const MetadataBlock::OwnerInfo *owner_info = metadata_content->owners()->Get(i);
                std::thread *ot = new std::thread(fetch_sieve_key_lambda, owner_info);
                fetch_sieve_key_t.push_back(ot);
            }

            for (auto t : fetch_sieve_key_t)
            {
                t->join();
                delete t;
            }
        }
        else
        {
            // Fetching from the cache
            assert(sieve_key_cache.find(metadata_uuid) != sieve_key_cache.end());
            owner_sieve_keys = sieve_key_cache[metadata_uuid];
        }

        /*
         Get Sieve data block
        */
        std::unordered_map<std::string, std::vector<uint8_t>> data_key_shares;
        std::vector<std::thread *> fetch_sieve_data_t;
        auto fetch_meta_lambda = [&](const MetadataBlock::OwnerInfo *owner_info)
        {
            std::unique_lock<std::mutex> data_lock(g_data_mutex, std::defer_lock);

            std::string owner_key_b64 = base64_encode(owner_info->owner_pubkey()->data(),
                                                      owner_info->owner_pubkey()->size());
            UUID sieve_data_uuid = UUID(owner_info->sieve_data_uuid()->str());
            char *enc_sieve_data_buf = nullptr;
            size_t enc_sieve_data_len = 0;

            conn = network_connect(get_storage_ip().c_str(), get_storage_port());
            err = download_file(conn, sieve_data_uuid, &enc_sieve_data_buf, &enc_sieve_data_len);

            // Decrypt Sieve data block
            uint8_t *sieve_data_buf = new uint8_t[enc_sieve_data_len]{};
            std::vector<int> hints_cast(owner_info->sieve_data_hint()->begin(),
                                        owner_info->sieve_data_hint()->end());
            owner_sieve_keys[owner_key_b64].decrypt(reinterpret_cast<const uint8_t *>(enc_sieve_data_buf),
                                                    enc_sieve_data_len,
                                                    sieve_data_buf,
                                                    hints_cast);

            // This memory copy prevents buffer overflow, since encrypted metadata might be longer
            // than metadata's memory size
            SieveDataBlock sieve_data_block;
            memcpy(&sieve_data_block, sieve_data_buf, sizeof(sieve_data_block));

#if !defined(NDEBUG)
            LOGV("Decrypted Sieve data:");
            hexprint(sieve_data_block.data_key, sizeof(sieve_data_block.data_key), 1);
#endif // NDEBUG

            data_lock.lock();
            data_key_shares[owner_key_b64].resize(sizeof(sieve_data_block.data_key));
            memcpy(&data_key_shares[owner_key_b64][0], sieve_data_block.data_key, sizeof(sieve_data_block.data_key));
            data_lock.unlock();

            delete[] enc_sieve_data_buf;
            delete[] sieve_data_buf;
        };

        // Fetch all Sieve-protected data key shares
        for (int i = 0; i < metadata_content->owners()->size(); i++)
        {
            auto owner_info = metadata_content->owners()->Get(i);
            std::thread *ot = new std::thread(fetch_meta_lambda, owner_info);
            fetch_sieve_data_t.push_back(ot);
        }

        for (auto t : fetch_sieve_data_t)
        {
            t->join();
            delete t;
        }

        /**
         * Fetch all data contents
         */
        struct DataEncBuf
        {
            char *buf = nullptr;
            size_t len = 0;
        };
        size_t data_enc_len = 0;
        size_t largest_cipher_chunk_size = G_DATA_BUF_SIZE;

        std::vector<DataEncBuf> data_enc_v;
        for (int i = 0; i < metadata_content->data_uuid()->size(); i++)
        {
            auto data_chunk_uuid_obj = metadata_content->data_uuid()->Get(i);
            DataEncBuf enc;
            UUID data_enc_uuid = UUID(data_chunk_uuid_obj->c_str(),
                                      data_chunk_uuid_obj->size());
            conn = network_connect(get_storage_ip().c_str(), get_storage_port());
            err = download_file(conn, data_enc_uuid, &enc.buf, &enc.len);
            data_enc_v.push_back(enc);
            data_enc_len += enc.len;
            largest_cipher_chunk_size = std::max(largest_cipher_chunk_size, enc.len);
        }

        // Contruct the full data
        uint8_t *data_enc_buf = new uint8_t[data_enc_len]{};
        int copied = 0;
        for (auto &enc : data_enc_v)
        {
            memcpy(&(data_enc_buf[copied]), enc.buf, enc.len);
            copied += enc.len;
            delete[] enc.buf;
        }

        /**
         * Construct data key from key shares
         */
        SharedSecretKey data_key;
        assemble_key_shares(data_key, data_key_shares);
        data_key.load_header_decryption(metadata_content->data_header()->data(),
                                        metadata_content->data_header()->size());

        uint8_t *data_buf = new uint8_t[data_enc_len]{};

        size_t processed = 0;
        size_t plain_offset = 0;

        // const size_t DATA_BUFFER_CIPHER_SIZE = SharedSecretKey::get_cipher_len(G_FILE_CHUNK_SIZE);
        while (processed < data_enc_len)
        {
            size_t chunk_cipher_len = std::min(largest_cipher_chunk_size, (size_t)data_enc_len - processed);

            size_t chunk_plain_len = SharedSecretKey::get_plain_len(chunk_cipher_len);

            try
            {
                data_key.decrypt(data_buf + plain_offset, 0,
                                 data_enc_buf + processed,
                                 chunk_cipher_len);
            }
            catch (...)
            {
                if (exp_fail)
                {
                    LOGI("Expected failure. Experienced failure!! Nice.");
                    return 0;
                }
                else
                {
                    throw "request access decryption fail";
                }
            }
            processed += chunk_cipher_len;
            plain_offset += chunk_plain_len;
        }

        if (!orig_file_path.empty())
        {
            char *orig_buf = nullptr;
            size_t orig_len = 0;
            read_from_file(orig_file_path, &orig_buf, &orig_len);

            if (memcmp(orig_buf, data_buf, orig_len) != 0)
            {
                LOGE("Decrypted data mismatch!");
            }
            else
            {
                LOGI("Decryption process matches!");
            }

            delete[] orig_buf;
        }

        if (store_output)
        {
            // Save decrypted data in temp directory
            char filename[] = "/tmp/teo-data.XXXXXX"; // template for our file.
            int fd = mkstemp(filename);             // Creates and opens a new temp file r/w.
                                                    // Xs are replaced with a unique number.
            if (fd == -1)
                return 1;        // Check we managed to open the file.
            write(fd, data_buf, plain_offset);
            close(fd);
            LOGI("Saved decrypted file at: %s", filename);
        }

        // Store key for cache and re-encryption tests
        sieve_key_cache[metadata_uuid] = owner_sieve_keys;

        delete[] data_buf;
        delete[] data_enc_buf;

        delete[] metadata_buf;
        delete[] accessor_pubkey;

        return 0;
    }
}