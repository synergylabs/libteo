// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_DATAREENCRYPTIONPREREQUEST_TEO_H_
#define FLATBUFFERS_GENERATED_DATAREENCRYPTIONPREREQUEST_TEO_H_

#include "flatbuffers/flatbuffers.h"

namespace teo {

struct DataReencryptionPreRequest;
struct DataReencryptionPreRequestBuilder;

struct DataReencryptionPreRequest FLATBUFFERS_FINAL_CLASS : private flatbuffers::Table {
  typedef DataReencryptionPreRequestBuilder Builder;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_CIPHERTEXT = 4
  };
  const flatbuffers::Vector<uint8_t> *ciphertext() const {
    return GetPointer<const flatbuffers::Vector<uint8_t> *>(VT_CIPHERTEXT);
  }
  bool Verify(flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffset(verifier, VT_CIPHERTEXT) &&
           verifier.VerifyVector(ciphertext()) &&
           verifier.EndTable();
  }
};

struct DataReencryptionPreRequestBuilder {
  typedef DataReencryptionPreRequest Table;
  flatbuffers::FlatBufferBuilder &fbb_;
  flatbuffers::uoffset_t start_;
  void add_ciphertext(flatbuffers::Offset<flatbuffers::Vector<uint8_t>> ciphertext) {
    fbb_.AddOffset(DataReencryptionPreRequest::VT_CIPHERTEXT, ciphertext);
  }
  explicit DataReencryptionPreRequestBuilder(flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  flatbuffers::Offset<DataReencryptionPreRequest> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = flatbuffers::Offset<DataReencryptionPreRequest>(end);
    return o;
  }
};

inline flatbuffers::Offset<DataReencryptionPreRequest> CreateDataReencryptionPreRequest(
    flatbuffers::FlatBufferBuilder &_fbb,
    flatbuffers::Offset<flatbuffers::Vector<uint8_t>> ciphertext = 0) {
  DataReencryptionPreRequestBuilder builder_(_fbb);
  builder_.add_ciphertext(ciphertext);
  return builder_.Finish();
}

inline flatbuffers::Offset<DataReencryptionPreRequest> CreateDataReencryptionPreRequestDirect(
    flatbuffers::FlatBufferBuilder &_fbb,
    const std::vector<uint8_t> *ciphertext = nullptr) {
  auto ciphertext__ = ciphertext ? _fbb.CreateVector<uint8_t>(*ciphertext) : 0;
  return teo::CreateDataReencryptionPreRequest(
      _fbb,
      ciphertext__);
}

inline const teo::DataReencryptionPreRequest *GetDataReencryptionPreRequest(const void *buf) {
  return flatbuffers::GetRoot<teo::DataReencryptionPreRequest>(buf);
}

inline const teo::DataReencryptionPreRequest *GetSizePrefixedDataReencryptionPreRequest(const void *buf) {
  return flatbuffers::GetSizePrefixedRoot<teo::DataReencryptionPreRequest>(buf);
}

inline bool VerifyDataReencryptionPreRequestBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<teo::DataReencryptionPreRequest>(nullptr);
}

inline bool VerifySizePrefixedDataReencryptionPreRequestBuffer(
    flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<teo::DataReencryptionPreRequest>(nullptr);
}

inline void FinishDataReencryptionPreRequestBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::DataReencryptionPreRequest> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedDataReencryptionPreRequestBuffer(
    flatbuffers::FlatBufferBuilder &fbb,
    flatbuffers::Offset<teo::DataReencryptionPreRequest> root) {
  fbb.FinishSizePrefixed(root);
}

}  // namespace teo

#endif  // FLATBUFFERS_GENERATED_DATAREENCRYPTIONPREREQUEST_TEO_H_