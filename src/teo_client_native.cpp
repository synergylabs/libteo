#include <cstring>

#if defined(TEO_STANDALONE_APP)
#include <iostream>
#include <linenoise.h>
#endif

#include "teo/CipherType.hpp"
#include "teo/SignatureType.hpp"
#include "teo/teo_client_native.hpp"
#include "teo/teo_logger.hpp"
#include "teo/teo_network.hpp"
#include "teo/base64.hpp"

namespace teo
{
    int admin_initialize_device_impl(const char *device_ip_load, const int device_port_in,
                                     const void *user_pubkey_ptr, size_t user_pubkey_len,
                                     SharedSecretKey &setup_key, AsymmetricEncryptionKeySet &keySet)
    {

        int sockfd = network_connect(device_ip_load, device_port_in);
        flatbuffers::FlatBufferBuilder builder(G_FBS_SIZE);

        // send Initialization Request
        CiphertextInitializationRequest request_payload;
        request_payload.type = CipherType::initialization_request;
        if (user_pubkey_ptr != nullptr)
        {
            memcpy(request_payload.admin_pubkey, user_pubkey_ptr, user_pubkey_len);
        }
        else
        {
            keySet.get_full_pk(request_payload.admin_pubkey, user_pubkey_len);
        }
        random_buf(request_payload.admin_challenge, G_CHALLENGE_SIZE);

        size_t request_ciphertext_len = SharedSecretKey::get_cipher_len(sizeof(request_payload));
        auto request_ciphertext = new uint8_t[request_ciphertext_len];
        setup_key.encrypt(request_ciphertext, request_ciphertext_len,
                          reinterpret_cast<const uint8_t *>(&request_payload),
                          sizeof(request_payload));

        auto setup_header_obj = builder.CreateVector(setup_key.get_header(),
                                                     SharedSecretKey::HEADER_SIZE);
        auto request_ciphertext_obj = builder.CreateVector(request_ciphertext,
                                                           request_ciphertext_len);
        auto request_msg = CreateInitializationRequest(builder, setup_header_obj,
                                                       request_ciphertext_obj);
        builder.Finish(request_msg);

        network_send_message_type(sockfd, MessageType_INITIALIZATION_REQUEST);
        network_send(sockfd, builder.GetBufferPointer(), builder.GetSize());

        // receive Initialization Device Info
        if (network_read_message_type(sockfd) != MessageType_INITIALIZATION_DEVICE_INFO)
        {
            LOGW("Unexpected device response during initialization");
            delete[] request_ciphertext;
            return -1;
        }

        uint8_t device_info_buf[READ_BUFFER_SIZE]{0};
        network_read(sockfd, device_info_buf, READ_BUFFER_SIZE);
        auto device_info_msg = GetInitializationDeviceInfo(device_info_buf);

        CiphertextInitializationDeviceInfo device_info;

        auto ciphertext_data = device_info_msg->ciphertext()->Data();
        auto ciphertext_data_len = device_info_msg->ciphertext()->size();

        keySet.box_seal_open(reinterpret_cast<uint8_t *>(&device_info),
                             sizeof(device_info),
                             ciphertext_data,
                             ciphertext_data_len);

        if (device_info.type != CipherType::initialization_device_info)
        {
            LOGW("Incorrect device info type");
            delete[] request_ciphertext;
            return -2;
        }
        if (memcmp(device_info.admin_challenge, request_payload.admin_challenge, G_CHALLENGE_SIZE) !=
            0)
        {
            LOGW("Incorrect initialization device info message!");
            delete[] request_ciphertext;
            return -3;
        }

        LOGV("Event: Initialization admin acquire device");

        // Create device proof
        SignatureDeviceProofContent device_proof_content;
        memcpy(device_proof_content.device_pubkey,
               device_info.device_pubkey, AsymmetricEncryptionKeySet::FULL_PK_SIZE);

        // Send Initialization Admin Reply
        CiphertextInitializationAdminReply reply_payload;
        reply_payload.type = CipherType::initialization_admin_reply;
        memcpy(reply_payload.device_challenge,
               device_info.device_challenge, G_CHALLENGE_SIZE);
        keySet.sign_detached(reply_payload.device_proof,
                             reinterpret_cast<const unsigned char *>(&device_proof_content),
                             sizeof(device_proof_content));
        uint8_t msg_nonce[AsymmetricEncryptionKeySet::NONCE_SIZE]{0};
        size_t admin_reply_ciphertext_len = AsymmetricEncryptionKeySet::get_box_easy_cipher_len(
            sizeof(reply_payload));
        auto admin_reply_ciphertext = new uint8_t[admin_reply_ciphertext_len];
        keySet.box_easy(admin_reply_ciphertext, admin_reply_ciphertext_len,
                        reinterpret_cast<const uint8_t *>(&reply_payload),
                        sizeof(reply_payload), msg_nonce, device_info.device_pubkey);

        builder.Clear();
        auto admin_reply_msg_nonce_obj = builder.CreateVector(msg_nonce,
                                                              AsymmetricEncryptionKeySet::NONCE_SIZE);
        auto admin_reply_ciphertext_obj = builder.CreateVector(admin_reply_ciphertext,
                                                               admin_reply_ciphertext_len);
        auto admin_reply_msg = CreateInitializationAdminReply(builder, admin_reply_msg_nonce_obj,
                                                              admin_reply_ciphertext_obj);
        builder.Finish(admin_reply_msg);

        network_send_message_type(sockfd, MessageType_INITIALIZATION_ADMIN_REPLY);
        network_send(sockfd, builder.GetBufferPointer(), builder.GetSize());

        delete[] request_ciphertext;
        delete[] admin_reply_ciphertext;

        return 0;
    }

    int admin_process_pre_auth_token_impl(uint8_t *request_buf,
                                          int connection,
                                          uint8_t *response_buf,
                                          int *response_len,
                                          AsymmetricEncryptionKeySet &keySet,
                                          bool interactive)
    {
        bool grant = true;
        auto request_msg = GetAcquirePreAuthTokenRequest(request_buf);

        SignaturePreAuthToken token_content;
        memcpy(token_content.user_pubkey, request_msg->user_pubkey()->Data(), request_msg->user_pubkey()->size());

        CiphertextAcquirePreAuthTokenResponse response_payload;
        response_payload.type = CipherType::acquire_pre_auth_token;
        keySet.sign_detached(response_payload.token,
                             reinterpret_cast<const unsigned char *>(&token_content),
                             sizeof(token_content));

#if defined(TEO_STANDALONE_APP)
        if (interactive)
        {
            linenoisePause();

            bool answer_valid = false;
            std::string answer;

            do
            {
                std::cout << "Do you want to grant this user pre-auth token? [y/n]: ";
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
        flatbuffers::FlatBufferBuilder builder(G_FBS_SIZE);
        uint8_t *ciphertext_buf = nullptr;

        if (grant)
        {
            LOGV("Event: Acquire pre auth token admin grant");
            LOGV("Token content base64: %s", base64_encode(response_payload.token, sizeof(response_payload.token)).c_str());

            uint8_t ciphertext_buf_len = AsymmetricEncryptionKeySet::get_box_easy_cipher_len(sizeof(response_payload));
            ciphertext_buf = new uint8_t[ciphertext_buf_len];
            uint8_t nonce[AsymmetricEncryptionKeySet::NONCE_SIZE];
            keySet.box_easy(ciphertext_buf, ciphertext_buf_len, reinterpret_cast<const uint8_t *>(&response_payload),
                            sizeof(response_payload), nonce, request_msg->user_pubkey()->Data());

            auto nonce_obj = builder.CreateVector(nonce, sizeof(nonce));
            auto ciphertext_obj = builder.CreateVector(ciphertext_buf, ciphertext_buf_len);
            auto response_msg = CreateAcquirePreAuthTokenResponse(builder, nonce_obj, ciphertext_obj);
            builder.Finish(response_msg);
        }
        else
        {
            LOGV("Event: Acquire pre auth token admin DENIED!!!!");
        }
#if defined(TEO_STANDALONE_APP)
        if (grant)
        {
            network_send_message_type(connection, MessageType_ACQUIRE_PRE_AUTH_TOKEN_RESPONSE);
            network_send(connection, builder.GetBufferPointer(), builder.GetSize());
        }
        else
        {
            close(connection);
        }
#else  // TEO_STANDALONE_APP
        int response_type_len = network_send_message_type(0,
                                                          MessageType_ACQUIRE_PRE_AUTH_TOKEN_RESPONSE,
                                                          response_buf);
        int response_content_len = network_send(0, builder.GetBufferPointer(), builder.GetSize(),
                                                SOCKET_SEND_FLAGS, response_buf + response_type_len);

        *response_len = response_type_len + response_content_len;
#endif // TEO_STANDALONE_APP
        if (ciphertext_buf != nullptr)
        {
            delete[] ciphertext_buf;
        }

        return 0;
    }

    int user_acquire_pre_auth_token_impl(const char *admin_ip_load, const int admin_port_in, const uint8_t *admin_pubkey,
                                         AsymmetricEncryptionKeySet &keySet, PreAuthToken &pre_auth_token)
    {
        int sockfd = network_connect(admin_ip_load, admin_port_in);

        flatbuffers::FlatBufferBuilder builder(G_FBS_SIZE);

        uint8_t pubkey_buf[AsymmetricEncryptionKeySet::FULL_PK_SIZE]{0};
        keySet.get_full_pk(pubkey_buf, sizeof(pubkey_buf));

        auto user_pubkey_obj = builder.CreateVector(pubkey_buf, sizeof(pubkey_buf));
        auto request_msg = CreateAcquirePreAuthTokenRequest(builder, user_pubkey_obj);
        builder.Finish(request_msg);

        network_send_message_type(sockfd, MessageType_ACQUIRE_PRE_AUTH_TOKEN_REQUEST);
        network_send(sockfd, builder.GetBufferPointer(), builder.GetSize());

        if (network_read_message_type(sockfd) != MessageType_ACQUIRE_PRE_AUTH_TOKEN_RESPONSE)
        {
            LOGW("Unexpected response type for pre auth token");
            return -1;
        }

        uint8_t response_buf[READ_BUFFER_SIZE]{0};
        network_read(sockfd, response_buf, READ_BUFFER_SIZE);
        auto response_msg = GetAcquirePreAuthTokenResponse(response_buf);

        CiphertextAcquirePreAuthTokenResponse response_payload;
        keySet.box_open_easy(reinterpret_cast<uint8_t *>(&response_payload), sizeof(response_payload),
                             response_msg->ciphertext()->data(), response_msg->ciphertext()->size(),
                             response_msg->box_nonce()->data(), admin_pubkey);

        if (response_payload.type != CipherType::acquire_pre_auth_token)
        {
            LOGW("Incorrect response type");
            return -1;
        }

        pre_auth_token = PreAuthToken(response_payload.token, sizeof(response_payload.token));

        LOGV("Event: Acquire pre auth token user receive\n");

        return 0;
    }

    int user_claim_device_impl(AsymmetricEncryptionKeySet &userKeySet, PreAuthToken &pre_auth_token,
                               const char *device_ip_load, const int device_port_in, const uint8_t *admin_pubkey,
                               bool exclusive, uint8_t *claimed_device, size_t claimed_device_len)
    {
        if (!pre_auth_token.is_initialized())
        {
            LOGW("Uninitialized pre auth token!");
            return -1;
        }

        int sockfd = network_connect(device_ip_load, device_port_in);

        flatbuffers::FlatBufferBuilder builder(G_FBS_SIZE);

        uint8_t user_pubkey[AsymmetricEncryptionKeySet::FULL_PK_SIZE]{};
        userKeySet.get_full_pk(user_pubkey, sizeof(user_pubkey));
        auto user_pubkey_obj = builder.CreateVector(user_pubkey, sizeof(user_pubkey));
        auto discovery_msg = CreateClaimDeviceDiscovery(builder, user_pubkey_obj);
        builder.Finish(discovery_msg);

        network_send_message_type(sockfd, MessageType_CLAIM_DEVICE_DISCOVERY);
        network_send(sockfd, builder.GetBufferPointer(), builder.GetSize());

        if (network_read_message_type(sockfd) != MessageType_CLAIM_DEVICE_DISCOVERY_RESPONSE)
        {
            LOGW("Unexpected message type");
            return -1;
        }

        uint8_t discovery_response_buf[READ_BUFFER_SIZE];
        network_read(sockfd, discovery_response_buf, sizeof(discovery_response_buf));
        auto discovery_response_msg = GetClaimDeviceDiscoveryResponse(discovery_response_buf);

        // Verify valid device proof
        SignatureDeviceProofContent expected_proof{};
        memcpy(expected_proof.device_pubkey, discovery_response_msg->device_pubkey()->Data(),
               discovery_response_msg->device_pubkey()->size());

        if (AsymmetricEncryptionKeySet::sign_verify_detached(discovery_response_msg->valid_device_proof()->Data(),
                                                             discovery_response_msg->valid_device_proof()->size(),
                                                             reinterpret_cast<const uint8_t *>(&expected_proof),
                                                             sizeof(expected_proof),
                                                             admin_pubkey) != 0)
        {
            LOGW("Invalid device proof");
            return -1;
        }

        CiphertextClaimDeviceRequest request_payload;
        request_payload.type = CipherType::claim_device_request;
        memcpy(request_payload.token, pre_auth_token.get_token(), PreAuthToken::get_token_len());
        random_buf(request_payload.user_challenge, sizeof(request_payload.user_challenge));

        size_t request_cipher_buf_len = AsymmetricEncryptionKeySet::
            get_box_easy_cipher_len(sizeof(request_payload));
        auto request_cipher_buf = new uint8_t[request_cipher_buf_len]{};
        uint8_t request_nonce[AsymmetricEncryptionKeySet::NONCE_SIZE]{};
        userKeySet.box_easy(request_cipher_buf, request_cipher_buf_len,
                            reinterpret_cast<const uint8_t *>(&request_payload), sizeof(request_payload),
                            request_nonce, discovery_response_msg->device_pubkey()->Data());

        builder.Clear();
        auto nonce_obj = builder.CreateVector(request_nonce, sizeof(request_nonce));
        auto ciphertext_obj = builder.CreateVector(request_cipher_buf, request_cipher_buf_len);
        int group_mode = exclusive ? 0 : 1;
        auto request_msg = CreateClaimDeviceRequest(builder, nonce_obj, ciphertext_obj, group_mode);
        builder.Finish(request_msg);

        network_send_message_type(sockfd, MessageType_CLAIM_DEVICE_REQUEST);
        network_send(sockfd, builder.GetBufferPointer(), builder.GetSize());

        if (network_read_message_type(sockfd) != MessageType_CLAIM_DEVICE_RESPONSE)
        {
            LOGW("Unexpected message for claim device response");
            delete[] request_cipher_buf;
            return -1;
        }

        uint8_t response_buf[READ_BUFFER_SIZE];
        network_read(sockfd, response_buf, sizeof(response_buf));
        auto response_msg = GetClaimDeviceResponse(response_buf);

        if (!response_msg->status())
        {
            LOGW("Device response is failure");
            delete[] request_cipher_buf;
            return -1;
        }

        CiphertextClaimDeviceResponse response_payload;
        userKeySet.box_open_easy(reinterpret_cast<uint8_t *>(&response_payload),
                                 sizeof(response_payload),
                                 response_msg->challenge_response_encrypted()->Data(),
                                 response_msg->challenge_response_encrypted()->size(),
                                 response_msg->response_nonce()->Data(),
                                 discovery_response_msg->device_pubkey()->Data());

        if (response_payload.type != CipherType::claim_device_response)
        {
            LOGW("Invalid response type");
            delete[] request_cipher_buf;
            return -1;
        }

        if (memcmp(response_payload.challenge_decrypted, request_payload.user_challenge,
                   sizeof(request_payload.user_challenge)) != 0)
        {
            LOGW("Mismatch challenge response");
            delete[] request_cipher_buf;
            return -1;
        }

        memcpy(claimed_device, discovery_response_msg->device_pubkey()->Data(), claimed_device_len);

        LOGV("Event: Claim device user finish device");

        delete[] request_cipher_buf;

        return 0;
    }

    int user_process_sieve_cred_request_impl(uint8_t *request_buf,
                                             int connection,
                                             uint8_t *response_buf,
                                             int *response_len,
                                             AsymmetricEncryptionKeySet &keySet,
                                             SieveKey &sieve_key,
                                             uint8_t *claimed_device,
                                             size_t claimed_device_len,
                                             uint8_t *request_pubkey,
                                             size_t request_pubkey_len)
    {
        auto request_msg = GetDataStoreSieveCredRequest(request_buf);

        CiphertextDataStoreSieveCredRequest request_payload;
        keySet.box_open_easy(reinterpret_cast<uint8_t *>(&request_payload), sizeof(request_payload),
                             request_msg->ciphertext()->Data(), request_msg->ciphertext()->size(),
                             request_msg->session_nonce()->Data(), request_msg->device_pubkey()->data());

        if (request_payload.type != CipherType::data_store_sieve_cred_request)
        {
            LOGW("Unexpected cred request type");
            return -1;
        }

        if (memcmp(claimed_device, request_msg->device_pubkey()->Data(), claimed_device_len) != 0)
        {
            LOGW("Didn't claim this device before. Abort.");
            return -1;
        }

        sieve_key = SieveKey();

        CiphertextDataStoreSieveCredResponse response_payload;
        response_payload.type = CipherType::data_store_sieve_cred_response;
        sieve_key.serialize_key_into(response_payload.sieve_key, sizeof(response_payload.sieve_key));
        sieve_key.serialize_nonce_into(response_payload.sieve_nonce, sizeof(response_payload.sieve_nonce));

        size_t response_cipher_len = keySet.get_box_easy_cipher_len(sizeof(response_payload));
        auto response_cipher = new uint8_t[response_cipher_len]{};
        uint8_t nonce[AsymmetricEncryptionKeySet::NONCE_SIZE];
        keySet.box_easy(response_cipher, response_cipher_len,
                        reinterpret_cast<uint8_t *>(&response_payload), sizeof(response_payload),
                        nonce, request_msg->device_pubkey()->data());

        flatbuffers::FlatBufferBuilder builder(G_FBS_SIZE);
        auto response_session_header_obj = builder.CreateVector(nonce, sizeof(nonce));
        auto response_cipher_obj = builder.CreateVector(response_cipher, response_cipher_len);
        auto response_msg = CreateDataStoreSieveCredResponse(builder, response_session_header_obj,
                                                             response_cipher_obj);
        builder.Finish(response_msg);

        memcpy(request_pubkey, request_msg->device_pubkey()->data(), request_pubkey_len);

#if defined(TEO_STANDALONE_APP)
        network_send_message_type(connection, MessageType_DATA_STORE_SIEVE_CRED_RESPONSE);
        network_send(connection, builder.GetBufferPointer(), builder.GetSize());
#else  // TEO_STANDALONE_APP
        int response_type_len = network_send_message_type(0,
                                                          MessageType_DATA_STORE_SIEVE_CRED_RESPONSE,
                                                          response_buf);
        int response_content_len = network_send(0, builder.GetBufferPointer(), builder.GetSize(),
                                                SOCKET_SEND_FLAGS, response_buf + response_type_len);

        *response_len = response_type_len + response_content_len;
#endif // TEO_STANDALONE_APP

        return 0;
    }

    int user_process_upload_notification_impl(uint8_t *notification_buf,
                                              uint8_t *request_pubkey,
                                              AsymmetricEncryptionKeySet &keySet,
                                              UUID &metadata_UUID,
                                              UUID &sieve_data_UUID)
    {
        auto notification_msg = DataStoreUpload::GetDataStoreUploadNotification(notification_buf);

        CiphertextDataStoreUploadNotification notification_payload;
        keySet.box_open_easy(reinterpret_cast<uint8_t *>(&notification_payload),
                             sizeof(notification_payload),
                             notification_msg->ciphertext()->data(),
                             notification_msg->ciphertext()->size(),
                             notification_msg->session_nonce_notification()->data(),
                             request_pubkey);

        if (notification_payload.type != CipherType::data_store_upload_notification)
        {
            LOGW("Unexpected data store notification type");
            return -1;
        }

        metadata_UUID = UUID(notification_payload.metadata_block_uuid,
                             sizeof(notification_payload.metadata_block_uuid));
        sieve_data_UUID = UUID(notification_payload.sieve_data_uuid,
                               sizeof(notification_payload.sieve_data_uuid));

        return 0;
    }

    int user_process_data_access_fetch_1_impl(uint8_t *fetch_buf,
                                              AsymmetricEncryptionKeySet &keySet,
                                              CiphertextDataAccessFetch &fetch_payload,
                                              uint8_t *accessor_pubkey,
                                              size_t accessor_pubkey_len)
    {
        auto fetch_msg = GetDataAccessFetch(fetch_buf);

        keySet.box_open_easy(reinterpret_cast<uint8_t *>(&fetch_payload), sizeof(fetch_payload),
                             fetch_msg->ciphertext()->data(), fetch_msg->ciphertext()->size(),
                             fetch_msg->message_nonce()->data(), fetch_msg->accessor_pubkey()->data());

        if (fetch_payload.type != CipherType::data_access_fetch)
        {
            LOGW("Wrong fetch request type");
            return -1;
        }

        if (accessor_pubkey_len != fetch_msg->accessor_pubkey()->size())
        {
            LOGW("Mismatch accessor pubkey buffer length!");
            return -1;
        }

        memcpy(accessor_pubkey, fetch_msg->accessor_pubkey()->data(), fetch_msg->accessor_pubkey()->size());

        return 0;
    }

    int user_process_data_access_fetch_2_impl(int connection,
                                              uint8_t *response_buf,
                                              int *response_len,
                                              AsymmetricEncryptionKeySet &keySet,
                                              SieveKey &sieve_key,
                                              CiphertextDataAccessFetch &fetch_payload,
                                              uint8_t *accessor_pubkey)
    {

        CiphertextDataAccessResponse response;
        response.type = CipherType::data_access_response;
        sieve_key.serialize_key_into(response.sieve_key, sizeof(response.sieve_key));
        memcpy(response.random_challenge_response,
               fetch_payload.random_challenge,
               sizeof(fetch_payload.random_challenge));

        uint8_t msg_nonce[AsymmetricEncryptionKeySet::NONCE_SIZE]{};

        size_t cipher_len = AsymmetricEncryptionKeySet::get_box_easy_cipher_len(sizeof(response));
        auto cipher = new uint8_t[cipher_len]{};
        keySet.box_easy(cipher, cipher_len, reinterpret_cast<const uint8_t *>(&response),
                        sizeof(response), msg_nonce, accessor_pubkey);

        flatbuffers::FlatBufferBuilder builder(G_FBS_SIZE);
        auto msg_nonce_obj = builder.CreateVector(msg_nonce, sizeof(msg_nonce));
        auto ciphertext_obj = builder.CreateVector(cipher, cipher_len);
        auto response_msg = CreateDataAccessResponse(builder, msg_nonce_obj, ciphertext_obj);
        builder.Finish(response_msg);

#if defined(TEO_STANDALONE_APP)
        network_send_message_type(connection, MessageType_DATA_ACCESS_RESPONSE);
        network_send(connection, builder.GetBufferPointer(), builder.GetSize());
#else  // TEO_STANDALONE_APP
        int response_type_len = network_send_message_type(0,
                                                          MessageType_DATA_ACCESS_RESPONSE,
                                                          response_buf);
        int response_content_len = network_send(0, builder.GetBufferPointer(), builder.GetSize(),
                                                SOCKET_SEND_FLAGS, response_buf + response_type_len);

        *response_len = response_type_len + response_content_len;
#endif // TEO_STANDALONE_APP
        return 0;
    }

    int user_re_encrypt_impl(const UUID &metadata_uuid,
                             const UUID &sieve_data_uuid,
                             RekeyToken &token,
                             const uint8_t *storage_pk,
                             const char *storage_ip,
                             uint16_t storage_port,
                             AsymmetricEncryptionKeySet &keySet)
    {
        uint8_t user_pubkey[AsymmetricEncryptionKeySet::FULL_PK_SIZE]{};
        keySet.get_full_pk(user_pubkey, sizeof(user_pubkey));

        const uint8_t *dynamic_pk = storage_pk;
        if (dynamic_pk == nullptr)
        {
            // Fetch storage's public key through out-of-band trusted KMS
            int conn = network_connect(storage_ip, storage_port);
            network_send_message_type(conn, MessageType_UTIL_FETCH_STORE_PUBKEY);
            uint8_t store_pk_buf[READ_BUFFER_SIZE]{};
            network_read(conn, store_pk_buf, sizeof(store_pk_buf));
            auto msg = GetUtilFetchStorePubkey(store_pk_buf);
            auto buf = new uint8_t[AsymmetricEncryptionKeySet::FULL_PK_SIZE]{};
            memcpy(buf, msg->pubkey()->data(), AsymmetricEncryptionKeySet::FULL_PK_SIZE);
            dynamic_pk = buf;
        }

        flatbuffers::FlatBufferBuilder builder(G_FBS_SIZE);
        size_t cipher_len = 0;
        uint8_t *cipher = nullptr;
        int conn = network_connect(storage_ip, storage_port);

        /**
         * Negotiate pre-request to prevent replay attack
         */
        // Send pre request
        CiphertextDataReencryptionPreRequest pre_req_payload;
        pre_req_payload.type = CipherType::data_reencryption_pre_request;
        memcpy(pre_req_payload.sieve_data_block_uuid,
               sieve_data_uuid.get_uuid().c_str(),
               sizeof(pre_req_payload.sieve_data_block_uuid));
        memcpy(pre_req_payload.metadata_uuid,
               metadata_uuid.get_uuid().c_str(),
               sizeof(pre_req_payload.metadata_uuid));
        random_buf(pre_req_payload.user_nonce, sizeof(pre_req_payload.user_nonce));

        cipher_len = AsymmetricEncryptionKeySet::get_box_seal_cipher_len(sizeof(pre_req_payload));
        delete[] cipher;
        cipher = new uint8_t[cipher_len]{0};

        keySet.box_seal(cipher, cipher_len,
                              reinterpret_cast<const uint8_t *>(&pre_req_payload),
                              sizeof(pre_req_payload), dynamic_pk);

        builder.Clear();
        auto pre_req_cipher_obj = builder.CreateVector(cipher, cipher_len);
        auto pre_req_msg = CreateDataReencryptionPreRequest(builder, pre_req_cipher_obj);
        builder.Finish(pre_req_msg);

        network_send_message_type(conn, MessageType_DATA_REENCRYPTION_PRE_REQUEST);
        network_send(conn, builder.GetBufferPointer(), builder.GetSize());

        // Process pre-response
        if (network_read_message_type(conn) != MessageType_DATA_REENCRYPTION_PRE_RESPONSE)
        {
            LOGW("Unexpected message for Pre-response!");
            return -1;
        }
        uint8_t pre_res_buf[READ_BUFFER_SIZE]{0};
        network_read(conn, pre_res_buf, sizeof(pre_res_buf));
        auto pre_res_msg = GetDataReencryptionPreResponse(pre_res_buf);
        CiphertextDataReencryptionPreResponse pre_res_payload;
        keySet.box_seal_open(reinterpret_cast<uint8_t *>(&pre_res_payload),
                                   sizeof(pre_res_payload),
                                   pre_res_msg->ciphertext()->data(),
                                   pre_res_msg->ciphertext()->size());

        if (pre_res_payload.type != CipherType::data_reencryption_pre_response)
        {
            LOGW("Wrong message type for pre response");
            return -1;
        }

        if (memcmp(pre_res_payload.user_nonce,
                   pre_req_payload.user_nonce,
                   sizeof(pre_res_payload.user_nonce)) != 0)
        {
            LOGW("Incorrect user nonce responded");
            return -1;
        }

        /**
         * Construct the main request
         */
        CiphertextDataReencryptionRequest request_payload;
        request_payload.type = CipherType::data_reencryption_request;
        memcpy(&(request_payload.rekey_token),
               reinterpret_cast<const uint8_t *>(&token),
               sizeof(token));
        random_buf(request_payload.noti_token, G_CHALLENGE_SIZE);
        memcpy(request_payload.user_nonce,
               pre_req_payload.user_nonce,
               sizeof(request_payload.user_nonce));
        memcpy(request_payload.storage_nonce,
               pre_res_payload.storage_nonce,
               sizeof(request_payload.storage_nonce));

        LOGV("Rekey token size: %d", sizeof(request_payload.rekey_token));

        cipher_len = AsymmetricEncryptionKeySet::get_box_easy_cipher_len(sizeof(request_payload));
        delete[] cipher;
        cipher = new uint8_t[cipher_len]{0};
        uint8_t nonce[AsymmetricEncryptionKeySet::NONCE_SIZE]{0};

        hexprint(dynamic_pk, AsymmetricEncryptionKeySet::FULL_PK_SIZE);
        keySet.box_easy(cipher, cipher_len, reinterpret_cast<const uint8_t *>(&request_payload),
                              sizeof(request_payload), nonce, dynamic_pk);

        builder.Clear();
        auto sieve_uuid_obj = builder.CreateString(sieve_data_uuid.get_uuid());
        auto owner_pk_obj = builder.CreateVector(user_pubkey, sizeof(user_pubkey));
        auto msg_nonce_obj = builder.CreateVector(nonce, sizeof(nonce));
        auto cipher_obj = builder.CreateVector(cipher, cipher_len);
        auto request_msg = CreateDataReencryptionRequest(builder, sieve_uuid_obj, owner_pk_obj, msg_nonce_obj, cipher_obj);
        builder.Finish(request_msg);

        network_send_message_type(conn, MessageType_DATA_REENCRYPTION_REQUEST);
        network_send(conn, builder.GetBufferPointer(), builder.GetSize());

        if (network_read_message_type(conn) != MessageType_DATA_REENCRYPTION_RESPONSE)
        {
            LOGW("Wrong reencryption response message type");
            return -1;
        }
        uint8_t res_buf[READ_BUFFER_SIZE]{0};
        network_read(conn, res_buf, sizeof(res_buf));
        auto res_msg = GetDataReencryptionResponse(res_buf);

        if (memcmp(res_msg->notification_token()->data(),
                   request_payload.noti_token,
                   sizeof(request_payload.noti_token)) != 0)
        {
            LOGW("Unmatched notification token!");
            return -1;
        }

        delete[] cipher;
        delete[] dynamic_pk;

        return 0;
    }

    int client_register_ip_kms_impl(const uint8_t *client_pubkey, size_t client_pubkey_len,
                                    const char *client_ip_load, const int client_port_in,
                                    const char *storage_ip_load, const int storage_port_in)
    {
        int conn = network_connect(storage_ip_load, storage_port_in);

        flatbuffers::FlatBufferBuilder builder(G_FBS_SIZE);
        auto pubkey_obj = builder.CreateVector(client_pubkey, client_pubkey_len);
        auto ip_obj = builder.CreateString(client_ip_load);
        auto register_msg = CreateUtilRegisterIp(builder, pubkey_obj, ip_obj, client_port_in);
        builder.Finish(register_msg);

        network_send_message_type(conn, MessageType_UTIL_REGISTER_IP);
        network_send(conn, builder.GetBufferPointer(), builder.GetSize());

        return 0;
    }

    int client_fetch_ip_kms_impl(const uint8_t *pk, size_t pk_len,
                                 const char *storage_ip_load, const int storage_port_in,
                                 std::string &res_ip, int &res_port)
    {
        assert(pk_len >= AsymmetricEncryptionKeySet::FULL_PK_SIZE);

        int conn = network_connect(storage_ip_load, storage_port_in);

        flatbuffers::FlatBufferBuilder builder(G_FBS_SIZE);
        auto pubkey_obj = builder.CreateVector(pk, pk_len);
        auto req_msg = CreateUtilFetchIpRequest(builder, pubkey_obj);
        builder.Finish(req_msg);

        network_send_message_type(conn, MessageType_UTIL_FETCH_IP_REQUEST);
        network_send(conn, builder.GetBufferPointer(), builder.GetSize());

        if (network_read_message_type(conn) != MessageType_UTIL_FETCH_IP_RESPONSE)
        {
            LOGW("Wrong response type from KMS");
            return -1;
        }

        uint8_t buf[G_DATA_BUF_SIZE]{};
        network_read(conn, buf, sizeof(buf));
        auto res_msg = GetUtilFetchIpResponse(buf);

        res_ip = std::string(res_msg->ip()->data());
        res_port = res_msg->port();

        return 0;
    }
}