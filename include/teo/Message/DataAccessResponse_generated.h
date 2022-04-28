// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_DATAACCESSRESPONSE_TEO_H_
#define FLATBUFFERS_GENERATED_DATAACCESSRESPONSE_TEO_H_

#include "flatbuffers/flatbuffers.h"

namespace teo {

struct DataAccessResponse;
struct DataAccessResponseBuilder;

struct DataAccessResponse FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef DataAccessResponseBuilder Builder;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_MSG_NONCE = 4,
    VT_CIPHERTEXT = 6
  };
  const flatbuffers::Vector<uint8_t> *msg_nonce() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_MSG_NONCE);
  }
  const flatbuffers::Vector<uint8_t> *ciphertext() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_CIPHERTEXT);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_MSG_NONCE) &&
           verifier.VerifyVector(msg_nonce()) &&
           VerifyOffset(verifier, VT_CIPHERTEXT) &&
           verifier.VerifyVector(ciphertext()) &&
           verifier.EndTable();
  }
};

struct DataAccessResponseBuilder {
  typedef DataAccessResponse Table;
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_msg_nonce(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> msg_nonce) {
    fbb_.AddOffset(DataAccessResponse::VT_MSG_NONCE, msg_nonce);
  }
  void add_ciphertext(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> ciphertext) {
    fbb_.AddOffset(DataAccessResponse::VT_CIPHERTEXT, ciphertext);
  }
  explicit DataAccessResponseBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  flatbuffers::Offset<DataAccessResponse> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<DataAccessResponse>(end);
    return o;
  }
};

inline flatbuffers::Offset<DataAccessResponse> CreateDataAccessResponse(
    flatbuffers::FlatBufferBuilder &_fbb,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> msg_nonce = 0,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> ciphertext = 0) {
  DataAccessResponseBuilder builder_(_fbb);
  builder_.add_ciphertext(ciphertext);
  builder_.add_msg_nonce(msg_nonce);
  return builder_.Finish();
}

inline flatbuffers::Offset<DataAccessResponse> CreateDataAccessResponseDirect(
    flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<uint8_t> *msg_nonce = nullptr,
    const std::vector<uint8_t> *ciphertext = nullptr) {
  auto msg_nonce__ = msg_nonce ? _fbb.CreateVector<uint8_t>(*msg_nonce) : 0;
  auto ciphertext__ = ciphertext ? _fbb.CreateVector<uint8_t>(*ciphertext) : 0;
  return teo::CreateDataAccessResponse(
      _fbb,
      msg_nonce__,
      ciphertext__);
}

inline const teo::DataAccessResponse *GetDataAccessResponse(const void *buf) {
  return flatbuffers::GetRoot<teo::DataAccessResponse>(buf);
}

inline const teo::DataAccessResponse *GetSizePrefixedDataAccessResponse(const void *buf) {
  return flatbuffers::GetSizePrefixedRoot<teo::DataAccessResponse>(buf);
}

inline bool VerifyDataAccessResponseBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<teo::DataAccessResponse>(nullptr);
}

inline bool VerifySizePrefixedDataAccessResponseBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<teo::DataAccessResponse>(nullptr);
}

inline void FinishDataAccessResponseBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::DataAccessResponse> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedDataAccessResponseBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::DataAccessResponse> root) {
  fbb.FinishSizePrefixed(root);
}

}  // namespace teo

#endif  // FLATBUFFERS_GENERATED_DATAACCESSRESPONSE_TEO_H_