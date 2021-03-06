// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_DATASTOREUPLOADNOTIFICATION_TEO_DATASTOREUPLOAD_H_
#define FLATBUFFERS_GENERATED_DATASTOREUPLOADNOTIFICATION_TEO_DATASTOREUPLOAD_H_

#include "flatbuffers/flatbuffers.h"

namespace teo {
namespace DataStoreUpload {

struct DataStoreUploadNotification;
struct DataStoreUploadNotificationBuilder;

struct DataStoreUploadNotification FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef DataStoreUploadNotificationBuilder Builder;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_SESSION_NONCE_NOTIFICATION = 4,
    VT_CIPHERTEXT = 6
  };
  const flatbuffers::Vector<uint8_t> *session_nonce_notification() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_SESSION_NONCE_NOTIFICATION);
  }
  const flatbuffers::Vector<uint8_t> *ciphertext() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_CIPHERTEXT);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_SESSION_NONCE_NOTIFICATION) &&
           verifier.VerifyVector(session_nonce_notification()) &&
           VerifyOffset(verifier, VT_CIPHERTEXT) &&
           verifier.VerifyVector(ciphertext()) &&
           verifier.EndTable();
  }
};

struct DataStoreUploadNotificationBuilder {
  typedef DataStoreUploadNotification Table;
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_session_nonce_notification(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> session_nonce_notification) {
    fbb_.AddOffset(DataStoreUploadNotification::VT_SESSION_NONCE_NOTIFICATION, session_nonce_notification);
  }
  void add_ciphertext(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> ciphertext) {
    fbb_.AddOffset(DataStoreUploadNotification::VT_CIPHERTEXT, ciphertext);
  }
  explicit DataStoreUploadNotificationBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  flatbuffers::Offset<DataStoreUploadNotification> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<DataStoreUploadNotification>(end);
    return o;
  }
};

inline flatbuffers::Offset<DataStoreUploadNotification> CreateDataStoreUploadNotification(
    flatbuffers::FlatBufferBuilder &_fbb,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> session_nonce_notification = 0,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> ciphertext = 0) {
  DataStoreUploadNotificationBuilder builder_(_fbb);
  builder_.add_ciphertext(ciphertext);
  builder_.add_session_nonce_notification(session_nonce_notification);
  return builder_.Finish();
}

inline flatbuffers::Offset<DataStoreUploadNotification> CreateDataStoreUploadNotificationDirect(
    flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<uint8_t> *session_nonce_notification = nullptr,
    const std::vector<uint8_t> *ciphertext = nullptr) {
  auto session_nonce_notification__ = session_nonce_notification ? _fbb.CreateVector<uint8_t>(*session_nonce_notification) : 0;
  auto ciphertext__ = ciphertext ? _fbb.CreateVector<uint8_t>(*ciphertext) : 0;
  return teo::DataStoreUpload::CreateDataStoreUploadNotification(
      _fbb,
      session_nonce_notification__,
      ciphertext__);
}

inline const teo::DataStoreUpload::DataStoreUploadNotification *GetDataStoreUploadNotification(const void *buf) {
  return flatbuffers::GetRoot<teo::DataStoreUpload::DataStoreUploadNotification>(buf);
}

inline const teo::DataStoreUpload::DataStoreUploadNotification *GetSizePrefixedDataStoreUploadNotification(const void *buf) {
  return flatbuffers::GetSizePrefixedRoot<teo::DataStoreUpload::DataStoreUploadNotification>(buf);
}

inline bool VerifyDataStoreUploadNotificationBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<teo::DataStoreUpload::DataStoreUploadNotification>(nullptr);
}

inline bool VerifySizePrefixedDataStoreUploadNotificationBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<teo::DataStoreUpload::DataStoreUploadNotification>(nullptr);
}

inline void FinishDataStoreUploadNotificationBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::DataStoreUpload::DataStoreUploadNotification> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedDataStoreUploadNotificationBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::DataStoreUpload::DataStoreUploadNotification> root) {
  fbb.FinishSizePrefixed(root);
}

}  // namespace DataStoreUpload
}  // namespace teo

#endif  // FLATBUFFERS_GENERATED_DATASTOREUPLOADNOTIFICATION_TEO_DATASTOREUPLOAD_H_
