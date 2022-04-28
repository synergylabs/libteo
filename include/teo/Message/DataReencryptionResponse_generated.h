// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_DATAREENCRYPTIONRESPONSE_TEO_H_
#define FLATBUFFERS_GENERATED_DATAREENCRYPTIONRESPONSE_TEO_H_

#include "flatbuffers/flatbuffers.h"

namespace teo {

struct DataReencryptionResponse;
struct DataReencryptionResponseBuilder;

struct DataReencryptionResponse FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef DataReencryptionResponseBuilder Builder;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_NOTIFICATION_TOKEN = 4
  };
  const flatbuffers::Vector<uint8_t> *notification_token() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_NOTIFICATION_TOKEN);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_NOTIFICATION_TOKEN) &&
           verifier.VerifyVector(notification_token()) &&
           verifier.EndTable();
  }
};

struct DataReencryptionResponseBuilder {
  typedef DataReencryptionResponse Table;
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_notification_token(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> notification_token) {
    fbb_.AddOffset(DataReencryptionResponse::VT_NOTIFICATION_TOKEN, notification_token);
  }
  explicit DataReencryptionResponseBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  flatbuffers::Offset<DataReencryptionResponse> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<DataReencryptionResponse>(end);
    return o;
  }
};

inline flatbuffers::Offset<DataReencryptionResponse> CreateDataReencryptionResponse(
    flatbuffers::FlatBufferBuilder &_fbb,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> notification_token = 0) {
  DataReencryptionResponseBuilder builder_(_fbb);
  builder_.add_notification_token(notification_token);
  return builder_.Finish();
}

inline flatbuffers::Offset<DataReencryptionResponse> CreateDataReencryptionResponseDirect(
    flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<uint8_t> *notification_token = nullptr) {
  auto notification_token__ = notification_token ? _fbb.CreateVector<uint8_t>(*notification_token) : 0;
  return teo::CreateDataReencryptionResponse(
      _fbb,
      notification_token__);
}

inline const teo::DataReencryptionResponse *GetDataReencryptionResponse(const void *buf) {
  return flatbuffers::GetRoot<teo::DataReencryptionResponse>(buf);
}

inline const teo::DataReencryptionResponse *GetSizePrefixedDataReencryptionResponse(const void *buf) {
  return flatbuffers::GetSizePrefixedRoot<teo::DataReencryptionResponse>(buf);
}

inline bool VerifyDataReencryptionResponseBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<teo::DataReencryptionResponse>(nullptr);
}

inline bool VerifySizePrefixedDataReencryptionResponseBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<teo::DataReencryptionResponse>(nullptr);
}

inline void FinishDataReencryptionResponseBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::DataReencryptionResponse> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedDataReencryptionResponseBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::DataReencryptionResponse> root) {
  fbb.FinishSizePrefixed(root);
}

}  // namespace teo

#endif  // FLATBUFFERS_GENERATED_DATAREENCRYPTIONRESPONSE_TEO_H_