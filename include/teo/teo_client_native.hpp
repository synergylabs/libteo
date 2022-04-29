// teo's Client interface to faciliate C/C++ native integration with mobile client
#ifndef TEO_TEO_CLIENT_NATIVE_H
#define TEO_TEO_CLIENT_NATIVE_H

#include "PreAuthToken.hpp"
#include "Sieve.hpp"
#include "SharedSecretKey.hpp"
#include "CipherType.hpp"

namespace teo
{
    int admin_initialize_device_impl(const char *device_ip_load, const int device_port_in,
                                     const void *user_pubkey_ptr, size_t user_pubkey_len,
                                     SharedSecretKey &setup_key,
                                     AsymmetricEncryptionKeySet &keySet);

    int admin_process_pre_auth_token_impl(uint8_t *request_buf,
                                          int connection,
                                          uint8_t *response_buf,
                                          int *response_len,
                                          AsymmetricEncryptionKeySet &keySet,
                                          bool interactive = false);

    int user_acquire_pre_auth_token_impl(const char *admin_ip_load, const int admin_port_in,
                                         const uint8_t *admin_pubkey,
                                         AsymmetricEncryptionKeySet &userKeySet,
                                         PreAuthToken &pre_auth_token);

    int user_claim_device_impl(AsymmetricEncryptionKeySet &userKeySet, PreAuthToken &pre_auth_token,
                               const char *device_ip_load, const int device_port_in, const uint8_t *admin_pubkey,
                               bool exclusive, uint8_t *claimed_device, size_t claimed_device_len);

    int user_process_sieve_cred_request_impl(uint8_t *request_buf,
                                             int connection,
                                             uint8_t *response_buf,
                                             int *response_len,
                                             AsymmetricEncryptionKeySet &keySet,
                                             SieveKey &sieve_key,
                                             uint8_t *claimed_device,
                                             size_t claimed_device_len,
                                             uint8_t *request_pubkey,
                                             size_t request_pubkey_len);

    int user_process_upload_notification_impl(uint8_t *notification_buf,
                                              uint8_t *request_pubkey,
                                              AsymmetricEncryptionKeySet &keySet,
                                              UUID &metadata_UUID,
                                              UUID &sieve_data_UUID);

    int user_process_data_access_fetch_1_impl(uint8_t *fetch_buf,
                                              AsymmetricEncryptionKeySet &keySet,
                                              CiphertextDataAccessFetch &fetch_payload,
                                              uint8_t *accessor_pubkey,
                                              size_t accessor_pubkey_len);

    int user_process_data_access_fetch_2_impl(int connection,
                                              uint8_t *response_buf,
                                              int *response_len,
                                              AsymmetricEncryptionKeySet &keySet,
                                              SieveKey &sieve_key,
                                              CiphertextDataAccessFetch &fetch_payload,
                                              uint8_t *accessor_pubkey);

    int client_register_ip_kms_impl(const uint8_t *client_pubkey, size_t client_pubkey_len,
                                    const char *client_ip_load, const int client_port_in,
                                    const char *storage_ip_load, const int storage_port_in);

    int client_fetch_ip_kms_impl(const uint8_t *query_pubkey, size_t query_pubkey_len,
                                 const char *storage_ip_load, const int storage_port_in,
                                 std::string &res_ip, int &res_port);
}

#endif // TEO_TEO_CLIENT_NATIVE_H
